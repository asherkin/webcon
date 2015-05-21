#ifndef _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_

#include "smsdk_ext.h"

class Webcon: public SDKExtension
{
public:
	virtual bool SDK_OnLoad(char *error, size_t maxlength, bool late);
	virtual void SDK_OnUnload();
	virtual bool QueryInterfaceDrop(SMInterface *interface);
	virtual void NotifyInterfaceDrop(SMInterface *interface);
};

#endif // _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
