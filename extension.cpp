#include "extension.h"

// tier1 supremecy
#include <netadr.h>
#include <utlvector.h>

#include "CDetour/detours.h"

#include "microhttpd.h"

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/ioctl.h>
#define closesocket close
#define ioctlsocket ioctl
#endif

Webcon g_Webcon;
SMEXT_LINK(&g_Webcon);

IGameConfig *gameConfig;

CDetour *detourProcessAccept;

MHD_Daemon *httpDaemon;

MHD_Response *responseUnauthorized;
MHD_Response *responseNotFound;

MHD_Response *responseIndexPage;

MHD_Response *responseQuitPage;
MHD_Response *responseQuitRedirect;

struct PendingSocket
{
	int timeout;
	int socket;
	sockaddr socketAddress;
	socklen_t socketAddressLength;
	netadr_t address;
};

CUtlVector<PendingSocket> pendingSockets;

struct ISocketCreatorListener
{
	virtual bool ShouldAcceptSocket(int socket, const netadr_t &address) = 0; 
	virtual void OnSocketAccepted(int socket, const netadr_t &address, void **data) = 0; 
	virtual void OnSocketClosed(int socket, const netadr_t &address, void *data) = 0;
};

struct CSocketCreator 
{
	// These are our own functions, they're in here for convenient access to the engine's CSocketCreator variables.
	void ProcessAccept();
	void HandSocketToEngine(PendingSocket *pendingSocket);

	struct AcceptedSocket
	{
		int socket;
		netadr_t address;
		void *data;
	};

	ISocketCreatorListener *listener;
	CUtlVector<AcceptedSocket> acceptedSockets;
	int listenSocket;
	netadr_t listenAddress;
};

void CSocketCreator::ProcessAccept()
{
	sockaddr socketAddress;
	socklen_t socketAddressLength = sizeof(socketAddress);
	int socket = accept(listenSocket, &socketAddress, &socketAddressLength);
	if (socket == -1) {
		return;
	}

	META_CONPRINTF("(%d) New listen socket accepted.\n", socket);

	int opt = 1;
	setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)); 

	opt = 1;
	setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

	opt = 1;
	if (ioctlsocket(socket, FIONBIO, (unsigned long *)&opt) == -1) {
		META_CONPRINTF("(%d) Failed to set socket options.\n", socket);
		closesocket(socket);
		return;
	}

	netadr_t address;
	address.SetFromSockadr(&socketAddress);

	if (listener && !listener->ShouldAcceptSocket(socket, address)) {
		META_CONPRINTF("(%d) Listener rejected connection.\n", socket);
		closesocket(socket);
		return;
	}

	PendingSocket *pendingSocket = &pendingSockets[pendingSockets.AddToTail()];
	pendingSocket->timeout = 0;
	pendingSocket->socket = socket;
	pendingSocket->socketAddress = socketAddress;
	pendingSocket->socketAddressLength = socketAddressLength;
	pendingSocket->address = address;
}

void CSocketCreator::HandSocketToEngine(PendingSocket *pendingSocket)
{
	AcceptedSocket *acceptedSocket = &acceptedSockets[acceptedSockets.AddToTail()];
	acceptedSocket->socket = pendingSocket->socket;
	acceptedSocket->address = pendingSocket->address;
	acceptedSocket->data = NULL;

	if (listener) {
		listener->OnSocketAccepted(acceptedSocket->socket, acceptedSocket->address, &(acceptedSocket->data));
	}
}

DETOUR_DECL_MEMBER0(ProcessAccept, void)
{
	// We DO NOT want to call the engine's implementation.
	//DETOUR_MEMBER_CALL(ProcessAccept)();

	CSocketCreator *creator = (CSocketCreator *)this;

	// Check for incoming sockets first.
	creator->ProcessAccept();

	// Just enough to verify if it is RCON or HTTP(S).
	unsigned char buffer[12];

	int count = pendingSockets.Count();
	for (int i = (count - 1); i >= 0; --i) {
		PendingSocket *pendingSocket = &pendingSockets[i];

		ssize_t ret = recv(pendingSocket->socket, (char *)buffer, sizeof(buffer), MSG_PEEK);

		if (ret <= 0) {
			if (ret == -1) {
#if _WIN32
				if (WSAGetLastError() == WSAEWOULDBLOCK) {
					continue;
				}

				META_CONPRINTF("(%d) recv error: %d\n", WSAGetLastError());
#else
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					continue;
				}

				META_CONPRINTF("(%d) recv error: %d\n", errno);
#endif
			}

			closesocket(pendingSocket->socket);
			META_CONPRINTF("(%d) Listen socket closed.\n", pendingSocket->socket);

			pendingSockets.Remove(i);
			continue;
		}

		// We need at least n bytes to identify packets.
		if ((size_t)ret < sizeof(buffer)) {
			pendingSocket->timeout++;

			// About 15 seconds.
			if (pendingSocket->timeout > 1000) {
				closesocket(pendingSocket->socket);
				META_CONPRINTF("(%d) Listen socket timed out.\n", pendingSocket->socket);

				pendingSockets.Remove(i);
			}

			continue;
		}

		META_CONPRINTF("(%d) Packet Header:", pendingSocket->socket);
		for (unsigned j = 0; j < sizeof(buffer); ++j) {
			META_CONPRINTF(" %02X", buffer[j]);
		}
		META_CONPRINTF("\n");

		bool isHttp = ((buffer[0] >= 'A' && buffer[0] <= 'Z') || (buffer[0] >= 'a' && buffer[0] <= 'z')) &&
		              ((buffer[1] >= 'A' && buffer[1] <= 'Z') || (buffer[1] >= 'a' && buffer[1] <= 'z')) &&
		              ((buffer[2] >= 'A' && buffer[2] <= 'Z') || (buffer[2] >= 'a' && buffer[2] <= 'z'));

		bool isHttps = buffer[0] == 0x16 && buffer[1] == 0x03 && buffer[5] == 0x01 && buffer[6] == 0x00 &&
		               ((buffer[3] * 256) + buffer[4]) == ((buffer[7] * 256) + buffer[8] + 4);

		bool isRcon = buffer[2] == 0x00 && buffer[3] == 0x00 &&
		              (buffer[8] == 0x03 && buffer[9] == 0x00 && buffer[10] == 0x00 && buffer[11] == 0x00);

		if (isHttp || isHttps) {
			MHD_add_connection(httpDaemon, pendingSocket->socket, &(pendingSocket->socketAddress), pendingSocket->socketAddressLength);
			META_CONPRINTF("(%d) Gave %s socket to web server.\n", pendingSocket->socket, isHttps ? "HTTPS" : "HTTP");
		} else if (isRcon) {
			creator->HandSocketToEngine(pendingSocket);
			META_CONPRINTF("(%d) Gave RCON socket to engine.\n", pendingSocket->socket);
		} else {
			closesocket(pendingSocket->socket);
			META_CONPRINTF("(%d) Unidentified protocol on socket.\n", pendingSocket->socket);
		}

		pendingSockets.Remove(i);
	}

	// Now everyone has their sockets, do HTTP work.
	MHD_run(httpDaemon);
}

int DefaultConnectionHandler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	if (strcmp(url, "/") == 0) {
		return MHD_queue_response(connection, MHD_HTTP_OK, responseIndexPage);
	}

	if (strcmp(url, "/quit") == 0) {
		// Yes, everyone knows this is awful, it's test code, shh.
		char *password = NULL;
		char *username = MHD_basic_auth_get_username_password(connection, &password);
		bool authorized = (username && password && strcmp(username, "srcds") == 0 && strcmp(password, "srcds") == 0);
		free(username);
		free(password);

		if (!authorized) {
			return MHD_queue_basic_auth_fail_response(connection, "SRCDS", responseUnauthorized);
		}

		if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
			META_CONPRINTF("SERVER QUIT (honest!)\n");

			return MHD_queue_response(connection, MHD_HTTP_FOUND, responseQuitRedirect);
		}

		return MHD_queue_response(connection, MHD_HTTP_OK, responseQuitPage);
	}
	
	META_CONPRINTF("Unhandled HTTP %s Request: %s\n", method, url);

	return MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, responseNotFound);
}

bool Webcon::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	if (!gameconfs->LoadGameConfigFile("webcon.games", &gameConfig, error, maxlength)) {
		return false;
	}

	CDetourManager::Init(smutils->GetScriptingEngine(), gameConfig);

	detourProcessAccept = DETOUR_CREATE_MEMBER(ProcessAccept, "ProcessAccept");
	if (!detourProcessAccept) {
		strncpy(error, "Error setting up ProcessAccept detour", maxlength);
		return false;
	}

	httpDaemon = MHD_start_daemon(MHD_USE_DEBUG | MHD_USE_NO_LISTEN_SOCKET, 0, NULL, NULL, &DefaultConnectionHandler, NULL, MHD_OPTION_END);
	if (!httpDaemon) {
		strncpy(error, "Failed to start HTTP server", maxlength);
		return false;
	}

	const char *contentUnauthorized = "<!DOCTYPE html>\n<html><body><h1>401 Unauthorized!</h1></body></html>";
	responseUnauthorized = MHD_create_response_from_buffer(strlen(contentUnauthorized), (void *)contentUnauthorized, MHD_RESPMEM_PERSISTENT);

	const char *contentNotFound = "<!DOCTYPE html>\n<html><body><h1>404 Not Found</h1></body></html>";
	responseNotFound = MHD_create_response_from_buffer(strlen(contentNotFound), (void *)contentNotFound, MHD_RESPMEM_PERSISTENT);

	const char *contentIndexPage = "<!DOCTYPE html>\n<html><body><h1>Hello, browser!</h1><a href=\"/quit\">Quit</a></body></html>";
	responseIndexPage = MHD_create_response_from_buffer(strlen(contentIndexPage), (void *)contentIndexPage, MHD_RESPMEM_PERSISTENT);

	const char *contentQuitPage = "<!DOCTYPE html>\n<html><body><h1>Quit</h1><form method=\"post\"><button type=\"submit\">Quit</button></form></body></html>";
	responseQuitPage = MHD_create_response_from_buffer(strlen(contentQuitPage), (void *)contentQuitPage, MHD_RESPMEM_PERSISTENT);

	const char *contentRedirect = "<!DOCTYPE html>\n<html><body><h1>Redirecting...</h1></body></html>";
	responseQuitRedirect = MHD_create_response_from_buffer(strlen(contentRedirect), (void *)contentRedirect, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(responseQuitRedirect, "Location", "/quit");

	detourProcessAccept->EnableDetour();

	return true;
}

void Webcon::SDK_OnUnload()
{
	detourProcessAccept->DisableDetour();

	MHD_destroy_response(responseUnauthorized);
	MHD_destroy_response(responseNotFound);
	MHD_destroy_response(responseIndexPage);
	MHD_destroy_response(responseQuitPage);
	MHD_destroy_response(responseQuitRedirect);

	MHD_stop_daemon(httpDaemon);

	gameconfs->CloseGameConfigFile(gameConfig);
}
