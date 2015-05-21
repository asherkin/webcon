#ifndef _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_

#include "smsdk_ext.h"
#include "public/IConplex.h"

class Conplex: public SDKExtension, IConplex
{
public: // SDKExtension
	virtual bool SDK_OnLoad(char *error, size_t maxlength, bool late);
	virtual void SDK_OnUnload();
	
public: // IConplex
	virtual unsigned int GetInterfaceVersion();
	virtual const char *GetInterfaceName();

	virtual bool RegisterProtocolHandler(const char *id, ProtocolDetectorCallback detector, ProtocolHandlerCallback handler);
	virtual bool DropProtocolHandler(const char *id);
};

#endif // _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
