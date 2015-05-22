#ifndef _INCLUDE_SOURCEMOD_CONPLEX_INTERFACE_H_
#define _INCLUDE_SOURCEMOD_CONPLEX_INTERFACE_H_

#include <IShareSys.h>

#define SMINTERFACE_CONPLEX_NAME "IConplex"
#define SMINTERFACE_CONPLEX_VERSION 1

struct sockaddr;

class IConplex: public SMInterface
{
public:
	virtual unsigned int GetInterfaceVersion() = 0;
	virtual const char *GetInterfaceName() = 0;

public:
	enum ProtocolDetectionState {
		NoMatch,
		NeedMoreData,
		Match,
	};

	typedef ProtocolDetectionState (*ProtocolDetectorCallback)(const char *id, const unsigned char *buffer, unsigned int bufferLength);
	typedef bool (*ProtocolHandlerCallback)(const char *id, int socket, const sockaddr *address, unsigned int addressLength);
	
public:
	virtual bool RegisterProtocolHandler(const char *id, ProtocolDetectorCallback detector, ProtocolHandlerCallback handler) = 0;
	virtual bool DropProtocolHandler(const char *id) = 0;
};

#endif //_INCLUDE_SOURCEMOD_CONPLEX_INTERFACE_H_
