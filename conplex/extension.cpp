#include "extension.h"

#include "CDetour/detours.h"

#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>
#define MSG_NOSIGNAL 0
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#define closesocket close
#define ioctlsocket ioctl
#define WSAGetLastError() errno
#endif

#if defined(_MSC_FULL_VER) && !defined (_SSIZE_T_DEFINED)
#define _SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#endif // !_SSIZE_T_DEFINED */

// tier1 supremecy
#include "utlvector.h"
#include "netadr.h"

#include "sm_namehashset.h"

Conplex g_Conplex;
SMEXT_LINK(&g_Conplex);

IGameConfig *gameConfig;

bool shouldHandleProcessAccept;

CDetour *detourProcessAccept;
CDetour *detourRunFrame;

HandleType_t handleTypeSocket;

struct SocketTypeHandler: public IHandleTypeDispatch
{
	void OnHandleDestroy(HandleType_t type, void *object);
};

SocketTypeHandler handlerSocketType;

void SocketTypeHandler::OnHandleDestroy(HandleType_t type, void *object)
{
	closesocket((int)object);
}

class ProtocolHandler
{
public:
	static bool matches(const char *key, const ProtocolHandler &value);

	ProtocolHandler(const char *id, IConplex::ProtocolDetectorCallback detector, IConplex::ProtocolHandlerCallback handler);
	ProtocolHandler(const char *id, IPluginContext *context, funcid_t detector, funcid_t handler);
	~ProtocolHandler();

	// TODO: Once we update to a version of SM with modern AMTL,
	// this needs to be converted to a move constructor.
	// (and the copy ctor deletes below can go)
	ProtocolHandler(ke::Moveable<ProtocolHandler> other);

	ProtocolHandler(ProtocolHandler const &other) = delete;
	ProtocolHandler &operator =(ProtocolHandler const &other) = delete;
	
public:
	const char *GetId() const;
	bool IsAlive() const;
	IConplex::ProtocolDetectionState ExecuteDetector(const unsigned char *buffer, unsigned int bufferLength) const;
	bool ExecuteHandler(int socket, const sockaddr *address, unsigned int addressLength) const;
	
	enum ProtocolHandlerType {
		Invalid,
		Extension,
		Plugin,
	};
	
private:
	char *id;
	ProtocolHandlerType type;
	IdentityToken_t *owner;
	
	union {
		IConplex::ProtocolDetectorCallback extension;
		IChangeableForward *plugin;
	} detector;
	
	union {
		IConplex::ProtocolHandlerCallback extension;
		IChangeableForward *plugin;
	} handler;
};

bool ProtocolHandler::matches(const char *key, const ProtocolHandler &value)
{
	return (strcmp(key, value.id) == 0);
}

ProtocolHandler::ProtocolHandler(const char *id, IConplex::ProtocolDetectorCallback detector, IConplex::ProtocolHandlerCallback handler)
{
	this->id = strdup(id);
	this->type = Extension;
	this->owner = NULL; // TODO: Pass this is.
	this->detector.extension = detector;
	this->handler.extension = handler;
}

ProtocolHandler::ProtocolHandler(const char *id, IPluginContext *context, funcid_t detector, funcid_t handler)
{
	this->id = strdup(id);
	this->type = Plugin;
	this->owner = context->GetIdentity();
	
	this->detector.plugin = forwards->CreateForwardEx(NULL, ET_Single, 3, NULL, Param_String, Param_String, Param_Cell);
	this->detector.plugin->AddFunction(context, detector);
	
	this->handler.plugin = forwards->CreateForwardEx(NULL, ET_Single, 3, NULL, Param_String, Param_Cell, Param_String);
	this->handler.plugin->AddFunction(context, handler);
}

ProtocolHandler::ProtocolHandler(ke::Moveable<ProtocolHandler> other)
{
	id = other->id;
	type = other->type;
	owner = other->owner;
	detector = other->detector;
	handler = other->handler;

	other->id = NULL;
	other->type = Invalid;
}

ProtocolHandler::~ProtocolHandler()
{
	free(id);
	
	if (this->type == Plugin) {
		if (detector.plugin) forwards->ReleaseForward(detector.plugin);
		if (handler.plugin) forwards->ReleaseForward(handler.plugin);
	}
}

const char *ProtocolHandler::GetId() const
{
	return id;
}

bool ProtocolHandler::IsAlive() const
{
	if (this->type == Plugin) {
		if (detector.plugin && detector.plugin->GetFunctionCount() <= 0) return false;
		if (handler.plugin && handler.plugin->GetFunctionCount() <= 0) return false;
	}
	
	return true;
}

IConplex::ProtocolDetectionState ProtocolHandler::ExecuteDetector(const unsigned char *buffer, unsigned int bufferLength) const
{
	if (this->type == Extension && detector.extension) {
		return detector.extension(id, buffer, bufferLength);
	}
	
	if (this->type == Plugin && detector.plugin) {
		detector.plugin->PushString(id);
		detector.plugin->PushStringEx((char *)buffer, bufferLength, SM_PARAM_STRING_COPY | SM_PARAM_STRING_BINARY, 0);
		detector.plugin->PushCell(bufferLength);
	
		cell_t result = 0;
		detector.plugin->Execute(&result);
		
		return (IConplex::ProtocolDetectionState)result;
	}
	
	return IConplex::NoMatch;
}

bool ProtocolHandler::ExecuteHandler(int socket, const sockaddr *address, unsigned int addressLength) const
{
	if (this->type == Extension && handler.extension) {
		return handler.extension(id, socket, address, addressLength);
	}
	
	if (this->type == Plugin && handler.plugin) {
		handler.plugin->PushString(id);
		handler.plugin->PushCell(handlesys->CreateHandle(handleTypeSocket, (void *)socket, owner, myself->GetIdentity(), NULL));
		handler.plugin->PushString(""); // TODO: inet_ntoa
	
		cell_t result = 0;
		handler.plugin->Execute(&result);
		
		return (result != 0);
	}
	
	return false;
}

NameHashSet<ProtocolHandler> protocolHandlers;

struct PendingSocket
{
	int timeout;
	int socket;
	sockaddr socketAddress;
	socklen_t socketAddressLength;
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
};

CRConServer *rconServer;

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
	void HandSocketToEngine(int socket, const sockaddr *socketAddress);

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

CSocketCreator *socketCreator;

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
}

void CSocketCreator::HandSocketToEngine(int socket, const sockaddr *socketAddress)
{
	netadr_t address;
	address.SetFromSockadr(socketAddress);

	AcceptedSocket *acceptedSocket = &acceptedSockets[acceptedSockets.AddToTail()];
	acceptedSocket->socket = socket;
	acceptedSocket->address = address;
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

	socketCreator = (CSocketCreator *)this;

	// Check for incoming sockets first.
	socketCreator->ProcessAccept();

	unsigned char buffer[32] = {};

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
		
		int pendingCount = 0;
		const ProtocolHandler *handler = NULL;
		
		if (ret > 0)
		{
			// TODO: Don't call handlers that have returned NoMatch already on a previous call for this connection.
			for (NameHashSet<ProtocolHandler>::iterator i = protocolHandlers.iter(); !i.empty(); i.next()) {
				if (!i->IsAlive()) {
					i.erase();
					continue;
				}
			
				IConplex::ProtocolDetectionState state = i->ExecuteDetector(buffer, ret);
				rootconsole->ConsolePrint(">>> %s = %d %d", i->GetId(), ret, state);
				
				if (state == IConplex::Match) {
					handler = &(*i);
					pendingCount = 0;
					break;
				}
				
				if (state == IConplex::NeedMoreData) {
					if (!handler) {
						handler = &(*i);
					}
				
					pendingCount++;
					continue;
				}
			}
		}
		
		if (pendingCount > 1) {
			handler = NULL;
		}

		if (!handler) {
			// Ran out of handlers or data.
			if ((ret > 0 && pendingCount == 0) || ret == sizeof(buffer)) {
				if (rconServer) {
					netadr_t address;
					address.SetFromSockadr(&(pendingSocket->socketAddress));
					rconServer->HandleFailedRconAuth(address);
				}

				rootconsole->ConsolePrint("(%d) Unidentified protocol on socket.", pendingSocket->socket);
				closesocket(pendingSocket->socket);

				pendingSockets.Remove(i);
				continue;
			}
		
			pendingSocket->timeout++;

			// About 15 seconds.
			if (pendingSocket->timeout > 1000) {
				if (rconServer) {
					// Unfortunately Chrome opens a number of extra connections without sending any data.
					//rconServer->HandleFailedRconAuth(pendingSocket->address);
				}

				rootconsole->ConsolePrint("(%d) Listen socket timed out.", pendingSocket->socket);
				closesocket(pendingSocket->socket);

				pendingSockets.Remove(i);
			}

			continue;
		}

		if (handler->ExecuteHandler(pendingSocket->socket, &(pendingSocket->socketAddress), pendingSocket->socketAddressLength)) {
			rootconsole->ConsolePrint("(%d) Gave %s socket to handler.", pendingSocket->socket, handler->GetId());
		} else {
			rootconsole->ConsolePrint("(%d) %s handler rejected socket.", pendingSocket->socket, handler->GetId());
			closesocket(pendingSocket->socket);
		}
		
		pendingSockets.Remove(i);
	}
}

DETOUR_DECL_MEMBER0(RunFrame, void)
{
	rconServer = (CRConServer *)this;

	shouldHandleProcessAccept = true;
	DETOUR_MEMBER_CALL(RunFrame)();
	shouldHandleProcessAccept = false;
}

IConplex::ProtocolDetectionState ConplexRConDetector(const char *id, const unsigned char *buffer, unsigned int bufferLength)
{
	if (bufferLength <= 2) return IConplex::NeedMoreData;
	if (buffer[2] != 0x00) return IConplex::NoMatch;
	if (bufferLength <= 3) return IConplex::NeedMoreData;
	if (buffer[3] != 0x00) return IConplex::NoMatch;
	if (bufferLength <= 8) return IConplex::NeedMoreData;
	if (buffer[8] != 0x03) return IConplex::NoMatch;
	if (bufferLength <= 9) return IConplex::NeedMoreData;
	if (buffer[9] != 0x00) return IConplex::NoMatch;
	if (bufferLength <= 10) return IConplex::NeedMoreData;
	if (buffer[10] != 0x00) return IConplex::NoMatch;
	if (bufferLength <= 11) return IConplex::NeedMoreData;
	if (buffer[11] != 0x00) return IConplex::NoMatch;
	return IConplex::Match;
}

bool ConplexRConHandler(const char *id, int socket, const sockaddr *address, unsigned int addressLength)
{
	if (!socketCreator) {
		return false;
	}
	
	socketCreator->HandSocketToEngine(socket, address);
	return true;
}

cell_t ConplexSocket_Send(IPluginContext *context, const cell_t *params)
{
	HandleSecurity security;
	security.pOwner = context->GetIdentity();
	security.pIdentity = myself->GetIdentity();

	int socket;
	HandleError error = handlesys->ReadHandle(params[1], handleTypeSocket, &security, (void **)&socket);
	if (error != HandleError_None) {
		return context->ThrowNativeError("Invalid socket handle %x (error %d)", params[1], error);
	}

	char *data = NULL;
	context->LocalToString(params[2], &data);

	ssize_t ret = send(socket, data, params[3], params[4] | MSG_NOSIGNAL);
	
	if (ret == -1 && SocketWouldBlock()) {
		return -2;
	}
	
	return ret;
}

cell_t ConplexSocket_Receive(IPluginContext *context, const cell_t *params)
{
	HandleSecurity security;
	security.pOwner = context->GetIdentity();
	security.pIdentity = myself->GetIdentity();

	int socket;
	HandleError error = handlesys->ReadHandle(params[1], handleTypeSocket, &security, (void **)&socket);
	if (error != HandleError_None) {
		return context->ThrowNativeError("Invalid socket handle %x (error %d)", params[1], error);
	}

	char *data = NULL;
	context->LocalToString(params[2], &data);

	ssize_t ret = recv(socket, data, params[3], params[4]);
	
	if (ret == -1 && SocketWouldBlock()) {
		return -2;
	}
	
	return ret;
}

cell_t Conplex_RegisterProtocol(IPluginContext *context, const cell_t *params)
{
	char *id = NULL;
	context->LocalToString(params[1], &id);
	if (id[0] == '\0') {
		return 0;
	}

	NameHashSet<ProtocolHandler>::Insert i = protocolHandlers.findForAdd(id);

	if (i.found()) {
		if (i->IsAlive()) {
			return 0;
		}

		protocolHandlers.remove(i);
		i = protocolHandlers.findForAdd(id);
	}

	ProtocolHandler ph(id, context, params[2], params[3]);
	protocolHandlers.add(i, ke::Moveable<ProtocolHandler>(ph));

	return 1;
}

sp_nativeinfo_t natives[] = {
	{"ConplexSocket.Send", ConplexSocket_Send},
	{"ConplexSocket.Receive", ConplexSocket_Receive},
	{"Conplex_RegisterProtocol", Conplex_RegisterProtocol},
	{NULL, NULL}
};

bool Conplex::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	if (!sharesys->AddInterface(myself, this))
	{
		strncpy(error, "Could not add IConplex interface", maxlength);
		return false;
	}
	
	if (!gameconfs->LoadGameConfigFile("conplex.games", &gameConfig, error, maxlength)) {
		return false;
	}

	CDetourManager::Init(smutils->GetScriptingEngine(), gameConfig);

	detourProcessAccept = DETOUR_CREATE_MEMBER(ProcessAccept, "ProcessAccept");
	if (!detourProcessAccept) {
		strncpy(error, "Error setting up ProcessAccept detour", maxlength);
		gameconfs->CloseGameConfigFile(gameConfig);
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

	detourProcessAccept->EnableDetour();
	
	if (detourRunFrame) {
		detourRunFrame->EnableDetour();
	}
	
	handleTypeSocket = handlesys->CreateType("ConplexSocket", &handlerSocketType, 0, NULL, NULL, myself->GetIdentity(), NULL);

	sharesys->AddNatives(myself, natives);
	
	RegisterProtocolHandler("RCon", ConplexRConDetector, ConplexRConHandler);

	return true;
}

void Conplex::SDK_OnUnload()
{
	handlesys->RemoveType(handleTypeSocket, myself->GetIdentity());
	
	if (detourRunFrame) {
		detourRunFrame->DisableDetour();
	}
	
	detourProcessAccept->DisableDetour();

	gameconfs->CloseGameConfigFile(gameConfig);
}

unsigned int Conplex::GetInterfaceVersion()
{
	return SMINTERFACE_CONPLEX_VERSION;
}

const char *Conplex::GetInterfaceName()
{
	return SMINTERFACE_CONPLEX_NAME;
}

bool Conplex::RegisterProtocolHandler(const char *id, ProtocolDetectorCallback detector, ProtocolHandlerCallback handler)
{
	NameHashSet<ProtocolHandler>::Insert i = protocolHandlers.findForAdd(id);

	if (i.found()) {
		if (i->IsAlive()) {
			return false;
		}

		protocolHandlers.remove(i);
		i = protocolHandlers.findForAdd(id);
	}

	ProtocolHandler ph(id, detector, handler);
	return protocolHandlers.add(i, ke::Moveable<ProtocolHandler>(ph));
}

bool Conplex::DropProtocolHandler(const char *id)
{
	return protocolHandlers.remove(id);
}
