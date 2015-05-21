#pragma semicolon 1
#pragma newdecls required

#include <webcon>

WebResponse indexResponse;
WebResponse googleResponse;
WebResponse avatarResponse;
WebResponse defaultResponse;

public void OnPluginStart()
{
	// Generate an ID so we can load multiple copies for testing.
	// Regular plugins should have a fixed, unique ID.
	char id[14];
	Format(id, sizeof(id), "test_%x", GetMyHandle());

	if (!Web_RegisterRequestHandler(id, OnWebRequest, "Webcon Test", "Test Webcon Responses")) {
		SetFailState("Failed to register request handler.");
	}

	indexResponse = new WebStringResponse("<!DOCTYPE html>\n<html><body><h1>Hello, World!</h1></body></html>");

	googleResponse = new WebStringResponse("<!DOCTYPE html>\n<html><body>Redirecting...</body></html>");
	googleResponse.AddHeader(WebHeader_Location, "https://google.com");

	avatarResponse = new WebFileResponse("avatar.png");
	avatarResponse.AddHeader(WebHeader_ContentType, "image/png");

	defaultResponse = new WebStringResponse("<!DOCTYPE html>\n<html><body><h1>404 Not Found</h1></body></html>");
}

// This isn't very good, but hey, test code.
void EscapeHTML(char[] buffer, int length)
{
	ReplaceString(buffer, length, "&", "&amp;");
	ReplaceString(buffer, length, "\"", "&quot;");
	ReplaceString(buffer, length, "'", "&#39;");
	ReplaceString(buffer, length, "<", "&lt;");
	ReplaceString(buffer, length, ">", "&gt;");
}

public bool OnWebRequest(WebConnection connection, const char[] method, const char[] url)
{
	char address[WEB_CLIENT_ADDRESS_LENGTH];
	connection.GetClientAddress(address, sizeof(address));

	PrintToServer(">>> (%x) %s - %s - %s", GetMyHandle(), address, method, url);

	if (StrEqual(url, "/")) {
		return connection.QueueResponse(WebStatus_OK, indexResponse);
	} 

	if (StrEqual(url, "/players")) {
		char buffer[12753];

		char name[187];
		for (int i = 1; i <= MaxClients; ++i) {
			if (!IsClientConnected(i)) {
				continue;
			}

			GetClientName(i, name, sizeof(name));
			EscapeHTML(name, sizeof(name));
			Format(buffer, sizeof(buffer), "%s<li>%s</li>", buffer, name);
		}

		Format(buffer, sizeof(buffer), "<!DOCTYPE html>\n<html><body><h1>Connected Players</h1><ul>%s</ul></body></html>", buffer);

		WebResponse response = new WebStringResponse(buffer);
		bool success = connection.QueueResponse(WebStatus_OK, response);
		delete response;

		return success;
	}

	if (StrEqual(url, "/google")) {
		return connection.QueueResponse(WebStatus_Found, googleResponse);
	}

	if (StrEqual(url, "/avatar")) {
		return connection.QueueResponse(WebStatus_OK, avatarResponse);
	}

	return connection.QueueResponse(WebStatus_NotFound, defaultResponse);
}
