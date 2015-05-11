#include <sourcemod>
#include <webcon>
#include <steamworks>

#pragma semicolon 1
#pragma newdecls required

#define OPENID_REALM "http://172.16.99.206:27015/manager/"
#define CLAIMED_ID_BASE "http://steamcommunity.com/openid/id/"

WebResponse indexResponse;
WebResponse steamRedirectResponse;
WebResponse notFoundResponse;

enum CheckAuthenticationState
{
	CheckAuthenticationState_Pending,
	CheckAuthenticationState_Error,
	CheckAuthenticationState_Forged,
	CheckAuthenticationState_Valid
}

ArrayList pendingCheckAuthenticationRequests;

public void OnPluginStart()
{
	if (!Web_RegisterRequestHandler("manager", OnWebRequest, "Manager", "Management Panel")) {
		SetFailState("Failed to register request handler.");
	}

	indexResponse = new WebStringResponse("<!DOCTYPE html>\n<a href=\"login\">Login</a>");
	indexResponse.AddHeader(WebHeader_ContentType, "text/html; charset=UTF-8");

	steamRedirectResponse = new WebStringResponse("Redirecting to Steam...");
	steamRedirectResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");
	steamRedirectResponse.AddHeader(WebHeader_Location, "https://steamcommunity.com/openid/login?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to="...OPENID_REALM..."login&openid.realm="...OPENID_REALM);

	notFoundResponse = new WebStringResponse("Not Found");
	notFoundResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");

	// WebConnection connection, CheckAuthenticationState state, DataPack steamid
	pendingCheckAuthenticationRequests = new ArrayList(3);
}

public int OnOpenIDCheckAuthenticationResponse(Handle request, bool failure, bool requestSuccessful, EHTTPStatusCode statusCode, WebConnection connection)
{
	int index = pendingCheckAuthenticationRequests.FindValue(connection);
	if (index == -1) {
		PrintToServer("Got a reply for a connection we're not waiting on o:");
		return 0;
	}

	if (failure || !requestSuccessful || statusCode != k_EHTTPStatusCode200OK) {
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Error, 1);
		return 0;
	}

	int bodySize;
	if (!SteamWorks_GetHTTPResponseBodySize(request, bodySize)) {
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Error, 1);
		return 0;
	}

	char[] body = new char[bodySize];
	if (!SteamWorks_GetHTTPResponseBodyData(request, body, bodySize)) {
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Error, 1);
		return 0;
	}

	if (StrContains(body, "is_valid:true") == -1) {
		// Forged OpenID request.
		PrintToServer(">>> Claim FAILED verification.");
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Forged, 1);
		return 0;
	}

	// We have a winner!
	PrintToServer(">>> Claim passed verification.");
	pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Valid, 1);

	return 0;
}

public bool OnWebRequest(WebConnection connection, const char[] method, const char[] url)
{
	if (StrEqual(url, "/login")) {
		int index = pendingCheckAuthenticationRequests.FindValue(connection);
		if (index != -1) {
			CheckAuthenticationState state = pendingCheckAuthenticationRequests.Get(index, 1);
			if (state == CheckAuthenticationState_Pending) {
				// Still waiting.
				return true;
			}

			DataPack steamidPack = pendingCheckAuthenticationRequests.Get(index, 2);
			steamidPack.Reset();

			char steamid[32];
			steamidPack.ReadString(steamid, sizeof(steamid));

			delete steamidPack;

			pendingCheckAuthenticationRequests.Erase(index);

			char buffer[256];
			if (state == CheckAuthenticationState_Valid) {
				FormatEx(buffer, sizeof(buffer), "Claim passed validation. (%s)", steamid);
			} else {
				FormatEx(buffer, sizeof(buffer), "Claim FAILED validation.");
			}

			WebResponse response = new WebStringResponse(buffer);
			response.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");

			bool success = connection.QueueResponse(WebStatus_OK, response);

			delete response;

			return success;
		}

		char openid_mode[256];
		if (!connection.GetRequestData(WebRequestDataType_Get, "openid.mode", openid_mode, sizeof(openid_mode)) || strcmp(openid_mode, "id_res") != 0) {
			return connection.QueueResponse(WebStatus_Found, steamRedirectResponse);
		}

		char openid_return_to[1024];
		if (!connection.GetRequestData(WebRequestDataType_Get, "openid.return_to", openid_return_to, sizeof(openid_return_to)) || strcmp(openid_return_to, OPENID_REALM..."login") != 0) {
			return connection.QueueResponse(WebStatus_Found, steamRedirectResponse);
		}

		char openid_claimed_id[1024];
		if (!connection.GetRequestData(WebRequestDataType_Get, "openid.claimed_id", openid_claimed_id, sizeof(openid_claimed_id)) || strncmp(openid_claimed_id, CLAIMED_ID_BASE, strlen(CLAIMED_ID_BASE)) != 0) {
			return connection.QueueResponse(WebStatus_Found, steamRedirectResponse);
		}

		char steamid[32];
		strcopy(steamid, sizeof(steamid), openid_claimed_id[strlen(CLAIMED_ID_BASE)]);

		PrintToServer(">>> Received valid-looking claim for '%s', waiting for verification...", steamid);

		DataPack steamidPack = new DataPack();
		steamidPack.WriteString(steamid);

		index = pendingCheckAuthenticationRequests.Push(connection);
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Pending, 1);
		pendingCheckAuthenticationRequests.Set(index, steamidPack, 2);
		
		// We don't have a sane way of iterating over all the params sent, but it should only be a subset of these.
		// "mode" is excluded because it needs to be added with a different value.
		// "return_to" and "claimed_id" are excluded because we need them anyway and can avoid copying them twice.
		char openid_fields[][] = {"openid.ns", "openid.op_endpoint", "openid.identity", "openid.response_nonce", "openid.invalidate_handle", "openid.assoc_handle", "openid.signed", "openid.sig"};

		Handle request = SteamWorks_CreateHTTPRequest(k_EHTTPMethodPOST, "https://steamcommunity.com/openid/login");

		SteamWorks_SetHTTPRequestContextValue(request, connection);
		SteamWorks_SetHTTPCallbacks(request, OnOpenIDCheckAuthenticationResponse);

		SteamWorks_SetHTTPRequestGetOrPostParameter(request, "openid.mode", "check_authentication");

		SteamWorks_SetHTTPRequestGetOrPostParameter(request, "openid.return_to", openid_return_to);
		SteamWorks_SetHTTPRequestGetOrPostParameter(request, "openid.claimed_id", openid_claimed_id);

		for (int i = 0; i < sizeof(openid_fields); ++i) {
			char openid_field[1024];
			if (!connection.GetRequestData(WebRequestDataType_Get, openid_fields[i], openid_field, sizeof(openid_field))) {
				continue;
			}

			SteamWorks_SetHTTPRequestGetOrPostParameter(request, openid_fields[i], openid_field);
		}

		SteamWorks_SendHTTPRequest(request);
		SteamWorks_PrioritizeHTTPRequest(request);

		// Don't queue a response, we'll get called every frame to check.
		return true;
	}

	if (StrEqual(url, "/")) {
		return connection.QueueResponse(WebStatus_OK, indexResponse);
	}

	return connection.QueueResponse(WebStatus_NotFound, notFoundResponse);
}
