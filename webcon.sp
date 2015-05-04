#pragma semicolon 1
#pragma newdecls required

#include <webcon>

public Action OnWebRequest(WebConnection connection, const char[] url, const char[] method)
{
	PrintToServer("(%s) %s", method, url);

	return Plugin_Continue;
}
