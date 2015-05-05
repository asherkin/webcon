#include "extension.h"

#include "CDetour/detours.h"

#include "microhttpd.h"

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#define closesocket close
#define ioctlsocket ioctl
#define WSAGetLastError() errno
#endif

// tier1 supremecy
#include "utlvector.h"
#include "netadr.h"

Webcon g_Webcon;
SMEXT_LINK(&g_Webcon);

IGameConfig *gameConfig;

bool shouldHandleProcessAccept;

CDetour *detourProcessAccept;
CDetour *detourRunFrame;

MHD_Daemon *httpDaemon;
MHD_Response *responseNotFound;

IForward *forwardRequest;

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

struct CRConServer: public ISocketCreatorListener
{
	static void *HandleFailedRconAuthFunction;
	bool HandleFailedRconAuth(const netadr_t &address);
} *rconServer;

void *CRConServer::HandleFailedRconAuthFunction = NULL;

bool CRConServer::HandleFailedRconAuth(const netadr_t &address)
{
	if (!CRConServer::HandleFailedRconAuthFunction) {
		return false;
	}

#ifdef _WIN32
	return ((bool (__fastcall *)(CRConServer *, void *, const netadr_t &))CRConServer::HandleFailedRconAuthFunction)(this, NULL, address);
#else
	return ((bool (*)(CRConServer *, const netadr_t &))CRConServer::HandleFailedRconAuthFunction)(this, address);
#endif
}

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

	rootconsole->ConsolePrint("(%d) New listen socket accepted.", socket);

	int opt = 1;
	setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt)); 

	opt = 1;
	setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

	opt = 1;
	if (ioctlsocket(socket, FIONBIO, (unsigned long *)&opt) == -1) {
		rootconsole->ConsolePrint("(%d) Failed to set socket options.", socket);
		closesocket(socket);
		return;
	}

	netadr_t address;
	address.SetFromSockadr(&socketAddress);

	if (listener && !listener->ShouldAcceptSocket(socket, address)) {
		rootconsole->ConsolePrint("(%d) Listener rejected connection.", socket);
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

bool SocketWouldBlock() {
#if _WIN32
	return (WSAGetLastError() == WSAEWOULDBLOCK);
#else
	return (errno == EAGAIN || errno == EWOULDBLOCK);
#endif
}

DETOUR_DECL_MEMBER0(ProcessAccept, void)
{
	if (!shouldHandleProcessAccept) {
		return DETOUR_MEMBER_CALL(ProcessAccept)();
	}

	CSocketCreator *creator = (CSocketCreator *)this;

	// Check for incoming sockets first.
	creator->ProcessAccept();

	// Just enough to verify if it is RCON or HTTP(S).
	unsigned char buffer[12];

	int count = pendingSockets.Count();
	for (int i = (count - 1); i >= 0; --i) {
		PendingSocket *pendingSocket = &pendingSockets[i];

		ssize_t ret = recv(pendingSocket->socket, (char *)buffer, sizeof(buffer), MSG_PEEK);

		if (ret == 0) {
			rootconsole->ConsolePrint("(%d) Listen socket closed.", pendingSocket->socket);
			closesocket(pendingSocket->socket);

			pendingSockets.Remove(i);
			continue;
		}

		if (ret == -1 && !SocketWouldBlock()) {
			rootconsole->ConsolePrint("(%d) recv error: %d", WSAGetLastError());
			closesocket(pendingSocket->socket);

			pendingSockets.Remove(i);
			continue;
		}

		// We need at least n bytes to identify packets.
		if (ret < (ssize_t)sizeof(buffer)) {
			pendingSocket->timeout++;

			// About 15 seconds.
			if (pendingSocket->timeout > 1000) {
				if (rconServer) {
					rconServer->HandleFailedRconAuth(pendingSocket->address);
				}

				rootconsole->ConsolePrint("(%d) Listen socket timed out.", pendingSocket->socket);
				closesocket(pendingSocket->socket);

				pendingSockets.Remove(i);
			}

			continue;
		}

#if 0
		META_CONPRINTF("(%d) Packet Header:", pendingSocket->socket);
		for (unsigned j = 0; j < sizeof(buffer); ++j) {
			META_CONPRINTF(" %02X", buffer[j]);
		}
		META_CONPRINTF("\n");
#endif

		bool isHttp = ((buffer[0] >= 'A' && buffer[0] <= 'Z') || (buffer[0] >= 'a' && buffer[0] <= 'z')) &&
		              ((buffer[1] >= 'A' && buffer[1] <= 'Z') || (buffer[1] >= 'a' && buffer[1] <= 'z')) &&
		              ((buffer[2] >= 'A' && buffer[2] <= 'Z') || (buffer[2] >= 'a' && buffer[2] <= 'z'));

		bool isHttps = buffer[0] == 0x16 && buffer[1] == 0x03 && buffer[5] == 0x01 && buffer[6] == 0x00 &&
		               ((buffer[3] * 256) + buffer[4]) == ((buffer[7] * 256) + buffer[8] + 4);

		bool isRcon = buffer[2] == 0x00 && buffer[3] == 0x00 &&
		              (buffer[8] == 0x03 && buffer[9] == 0x00 && buffer[10] == 0x00 && buffer[11] == 0x00);

		if (isHttp || isHttps) {
			MHD_add_connection(httpDaemon, pendingSocket->socket, &(pendingSocket->socketAddress), pendingSocket->socketAddressLength);
			rootconsole->ConsolePrint("(%d) Gave %s socket to web server.", pendingSocket->socket, isHttps ? "HTTPS" : "HTTP");
		} else if (isRcon) {
			creator->HandSocketToEngine(pendingSocket);
			rootconsole->ConsolePrint("(%d) Gave RCON socket to engine.", pendingSocket->socket);
		} else {
			if (rconServer) {
				rconServer->HandleFailedRconAuth(pendingSocket->address);
			}

			rootconsole->ConsolePrint("(%d) Unidentified protocol on socket.", pendingSocket->socket);
			closesocket(pendingSocket->socket);
		}

		pendingSockets.Remove(i);
	}

	// Now everyone has their sockets, do HTTP work.
	MHD_run(httpDaemon);
}

DETOUR_DECL_MEMBER0(RunFrame, void)
{
	rconServer = (CRConServer *)this;

	shouldHandleProcessAccept = true;
	DETOUR_MEMBER_CALL(RunFrame)();
	shouldHandleProcessAccept = false;
}

int DefaultConnectionHandler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	forwardRequest->PushCell(0);
	forwardRequest->PushString(url);
	forwardRequest->PushString(method);
	forwardRequest->Execute(NULL);

	// Blindly queue this for now.
	MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, responseNotFound);

	return MHD_YES;
}

void *LogRequestCallback(void *cls, const char *uri, struct MHD_Connection *con)
{
	char *ip = inet_ntoa(((sockaddr_in *const)MHD_get_connection_info(con, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr)->sin_addr);
	smutils->LogMessage(myself, "Request from %s: %s", ip, uri);
	return NULL;
}

void LogErrorCallback(void *cls, const char *fm, va_list ap)
{
	char buffer[2048];
	smutils->FormatArgs(buffer, sizeof(buffer), fm, ap);
	smutils->LogError(myself, "%s", buffer);
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

	detourRunFrame = DETOUR_CREATE_MEMBER(RunFrame, "RunFrame");
	if (!detourRunFrame) {
		shouldHandleProcessAccept = true;
		smutils->LogError(myself, "WARNING: Error setting up RunFrame detour, all TCP sockets will be hooked.");
	}

	if (!gameConfig->GetMemSig("HandleFailedRconAuth", &CRConServer::HandleFailedRconAuthFunction)) {
		smutils->LogError(myself, "WARNING: HandleFailedRconAuth not found in gamedata, bad clients will not be banned.");
	} else if (!CRConServer::HandleFailedRconAuthFunction) {
		smutils->LogError(myself, "WARNING: Scan for HandleFailedRconAuth failed, bad clients will not be banned.");
	}

	httpDaemon = MHD_start_daemon(MHD_USE_DEBUG | MHD_USE_NO_LISTEN_SOCKET, 0, NULL, NULL, &DefaultConnectionHandler, NULL, MHD_OPTION_URI_LOG_CALLBACK, LogRequestCallback, NULL, MHD_OPTION_EXTERNAL_LOGGER, LogErrorCallback, NULL, MHD_OPTION_END);
	if (!httpDaemon) {
		strncpy(error, "Failed to start HTTP server", maxlength);
		return false;
	}

	const char *contentNotFound = "<!DOCTYPE html>\n<html><body><h1>404 Not Found</h1></body></html>";
	responseNotFound = MHD_create_response_from_buffer(strlen(contentNotFound), (void *)contentNotFound, MHD_RESPMEM_PERSISTENT);

	forwardRequest = forwards->CreateForward("OnWebRequest", ET_Hook, 3, NULL, Param_Cell, Param_String, Param_String);

	detourProcessAccept->EnableDetour();
	
	if (detourRunFrame) {
		detourRunFrame->EnableDetour();
	}

	return true;
}

void Webcon::SDK_OnUnload()
{
	if (detourRunFrame) {
		detourRunFrame->DisableDetour();
	}
	
	detourProcessAccept->DisableDetour();

	forwards->ReleaseForward(forwardRequest);

	MHD_destroy_response(responseNotFound);

	MHD_stop_daemon(httpDaemon);

	gameconfs->CloseGameConfigFile(gameConfig);
}
