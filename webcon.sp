#pragma semicolon 1
#pragma newdecls required

#include <webcon>

WebResponse indexResponse;
WebResponse googleResponse;

public void OnPluginStart()
{
	indexResponse = new WebResponse("<!DOCTYPE html>\n<html><body><h1>Hello, World!</h1></body></html>");

	googleResponse = new WebResponse("<!DOCTYPE html>\n<html><body>Redirecting...</body></html>");
	googleResponse.AddHeader(WebHeader_Location, "https://google.com");
}

// This isn't very good, but hey, test code.
void EscapeHTML(char[] buffer, int length)
{
	ReplaceString(buffer, length, "&", "&amp;");
	ReplaceString(buffer, length, "\"", "&quot;");
	ReplaceString(buffer, length, "'", "&apos;");
	ReplaceString(buffer, length, "<", "&lt;");
	ReplaceString(buffer, length, ">", "&gt;");
}

public Action OnWebRequest(WebConnection connection, const char[] url, const char[] method)
{
	char address[WEB_CLIENT_ADDRESS_LENGTH];
	connection.GetClientAddress(address, sizeof(address));

	PrintToServer("%s - %s - %s", address, method, url);

	if (StrEqual(url, "/")) {
		connection.QueueResponse(WebStatus_OK, indexResponse);

		return Plugin_Stop;
	} 

	if (StrEqual(url, "/players")) {
		char buffer[2048];

		char name[65];
		for (int i = 1; i <= MaxClients; ++i) {
			if (!IsClientConnected(i)) {
				continue;
			}

			GetClientName(i, name, sizeof(name));
			EscapeHTML(name, sizeof(name));
			Format(buffer, sizeof(buffer), "%s<li>%s</li>", buffer, name);
		}

		Format(buffer, sizeof(buffer), "<!DOCTYPE html>\n<html><body><h1>Connected Players</h1><ul>%s</ul></body></html>", buffer);

		WebResponse response = new WebResponse(buffer);
		connection.QueueResponse(WebStatus_OK, response);
		delete response;

		return Plugin_Stop;
	}

	if (StrEqual(url, "/google")) {
		connection.QueueResponse(WebStatus_Found, googleResponse);

		return Plugin_Stop;
	} 

	return Plugin_Continue;
}
