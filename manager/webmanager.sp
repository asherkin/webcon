#include <sourcemod>
#include <webcon>
#include <steamworks>

#pragma semicolon 1
#pragma newdecls required

#define SESSION_ID_LENGTH 33
#define CLAIMED_ID_BASE "http://steamcommunity.com/openid/id/"

ConVar managerUrl;

WebResponse indexResponse;
WebResponse steamRedirectResponse;
WebResponse topSecretResponse;
WebResponse loginRedirectResponse;
WebResponse forbiddenResponse;
WebResponse notFoundResponse;

enum CheckAuthenticationState:
{
	CheckAuthenticationState_Pending,
	CheckAuthenticationState_Error,
	CheckAuthenticationState_Forged,
	CheckAuthenticationState_Valid,
};

// We can't use a named enum here because Pawn considers named enums starting with an uppercase letter to be strongly-typed
// (and thus it won't coerce to int when we need it). The ugly _MAX element is a slightly better trade-off than breaking style.
enum
{
	CheckAuthenticationData_Connection,
	CheckAuthenticationData_State,
	CheckAuthenticationData_SteamId,
	
	CheckAuthenticationData_MAX,
};

ArrayList pendingCheckAuthenticationRequests;

StringMap sessions;

public void OnPluginStart()
{
	if (!Web_RegisterRequestHandler("manager", OnWebRequest, "Manager", "Management Panel")) {
		SetFailState("Failed to register request handler.");
	}
	
	managerUrl = CreateConVar("webmanager_url", "", "Canonical URL for Web Manager. Must include trailing slash.");
	managerUrl.AddChangeHook(OnManagerUrlChanged);
	
	AutoExecConfig();

	indexResponse = new WebStringResponse("<!DOCTYPE html>\n<a href=\"login\">Login</a><br><a href=\"secret\">Secret</a>");
	indexResponse.AddHeader(WebHeader_ContentType, "text/html; charset=UTF-8");
	
	steamRedirectResponse = new WebStringResponse("The silly server admin needs to configure webmanager_url.");
	steamRedirectResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");

	topSecretResponse = new WebStringResponse("This is Top Secret!");
	topSecretResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");
	
	loginRedirectResponse = new WebStringResponse("This action requires authentication.");
	loginRedirectResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");

	forbiddenResponse = new WebStringResponse("Forbidden");
	forbiddenResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");

	notFoundResponse = new WebStringResponse("Not Found");
	notFoundResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");

	pendingCheckAuthenticationRequests = new ArrayList(CheckAuthenticationData_MAX);
	
	sessions = new StringMap();
}

public void OnManagerUrlChanged(ConVar convar, const char[] oldValue, const char[] newValue)
{
	if (newValue[0] == '\0') {
		return;
	}
	
	char buffer[1024];
	FormatEx(buffer, sizeof(buffer), "https://steamcommunity.com/openid/login?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.return_to=%slogin&openid.realm=%s", newValue, newValue);
	
	delete steamRedirectResponse;
	
	steamRedirectResponse = new WebStringResponse("Redirecting to Steam...");
	steamRedirectResponse.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");
	steamRedirectResponse.AddHeader(WebHeader_SetCookie, "id=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly");
	steamRedirectResponse.AddHeader(WebHeader_Location, buffer);
	
	FormatEx(buffer, sizeof(buffer), "%slogin", newValue);
	
	loginRedirectResponse.RemoveHeader(WebHeader_Location);
	loginRedirectResponse.AddHeader(WebHeader_Location, buffer);
}

public int OnOpenIdCheckAuthenticationResponse(Handle request, bool failure, bool requestSuccessful, EHTTPStatusCode statusCode, WebConnection connection)
{
	int index = pendingCheckAuthenticationRequests.FindValue(connection);
	if (index == -1) {
		PrintToServer("Got a reply for a connection we're not waiting on o:");
		delete request;
		return 0;
	}

	if (failure || !requestSuccessful || statusCode != k_EHTTPStatusCode200OK) {
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Error, CheckAuthenticationData_State);
		delete request;
		return 0;
	}

	int bodySize;
	if (!SteamWorks_GetHTTPResponseBodySize(request, bodySize)) {
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Error, CheckAuthenticationData_State);
		delete request;
		return 0;
	}

	char[] body = new char[bodySize];
	if (!SteamWorks_GetHTTPResponseBodyData(request, body, bodySize)) {
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Error, CheckAuthenticationData_State);
		delete request;
		return 0;
	}

	if (StrContains(body, "is_valid:true") == -1) {
		// Forged OpenID request.
		PrintToServer(">>> Claim FAILED verification.");
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Forged, CheckAuthenticationData_State);
		delete request;
		return 0;
	}

	// We have a winner!
	PrintToServer(">>> Claim passed verification.");
	pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Valid, CheckAuthenticationData_State);

	delete request;
	return 0;
}

void GenerateSessionId(char id[SESSION_ID_LENGTH])
{
	FormatEx(id, sizeof(id), "%08x%08x%08x%08x", GetURandomInt(), GetURandomInt(), GetURandomInt(), GetURandomInt());
}

public bool OnWebRequest(WebConnection connection, const char[] method, const char[] url)
{
	if (StrEqual(url, "/login")) {
		int index = pendingCheckAuthenticationRequests.FindValue(connection);
		if (index != -1) {
			CheckAuthenticationState state = pendingCheckAuthenticationRequests.Get(index, CheckAuthenticationData_State);
			if (state == CheckAuthenticationState_Pending) {
				// Still waiting.
				return true;
			}

			DataPack steamidPack = pendingCheckAuthenticationRequests.Get(index, CheckAuthenticationData_SteamId);
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

			WebStatus status = WebStatus_OK;
			WebResponse response = new WebStringResponse(buffer);
			response.AddHeader(WebHeader_ContentType, "text/plain; charset=UTF-8");
			
			if (state == CheckAuthenticationState_Valid) {
				char id[SESSION_ID_LENGTH];
				GenerateSessionId(id);
				
				char ip[WEB_CLIENT_ADDRESS_LENGTH];
				connection.GetClientAddress(ip, sizeof(ip));
				
				DataPack sessionPack = new DataPack();
				sessionPack.WriteString(ip);
				sessionPack.WriteString(steamid);
				
				sessions.SetValue(id, sessionPack);
			
				FormatEx(buffer, sizeof(buffer), "id=%s; HttpOnly", id);
				response.AddHeader(WebHeader_SetCookie, buffer);
				
				char return_url[1024];
				managerUrl.GetString(return_url, sizeof(return_url));
				StrCat(return_url, sizeof(return_url), "secret");
				response.AddHeader(WebHeader_Location, return_url);
				
				status = WebStatus_Found;
			}

			bool success = connection.QueueResponse(status, response);

			delete response;

			return success;
		}

		char openid_mode[256];
		if (!connection.GetRequestData(WebRequestDataType_Get, "openid.mode", openid_mode, sizeof(openid_mode)) || strcmp(openid_mode, "id_res") != 0) {
			return connection.QueueResponse(WebStatus_Found, steamRedirectResponse);
		}
		
		char return_to[1024];
		managerUrl.GetString(return_to, sizeof(return_to));
		StrCat(return_to, sizeof(return_to), "login");

		char openid_return_to[1024];
		if (!connection.GetRequestData(WebRequestDataType_Get, "openid.return_to", openid_return_to, sizeof(openid_return_to)) || strcmp(openid_return_to, return_to) != 0) {
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
		pendingCheckAuthenticationRequests.Set(index, CheckAuthenticationState_Pending, CheckAuthenticationData_State);
		pendingCheckAuthenticationRequests.Set(index, steamidPack, CheckAuthenticationData_SteamId);
		
		// We don't have a sane way of iterating over all the params sent, but it should only be a subset of these.
		// "mode" is excluded because it needs to be added with a different value.
		// "return_to" and "claimed_id" are excluded because we need them anyway and can avoid copying them twice.
		char openid_fields[][] = {"openid.ns", "openid.op_endpoint", "openid.identity", "openid.response_nonce", "openid.invalidate_handle", "openid.assoc_handle", "openid.signed", "openid.sig"};

		Handle request = SteamWorks_CreateHTTPRequest(k_EHTTPMethodPOST, "https://steamcommunity.com/openid/login");

		SteamWorks_SetHTTPRequestContextValue(request, connection);
		SteamWorks_SetHTTPCallbacks(request, OnOpenIdCheckAuthenticationResponse);

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

	if (StrEqual(url, "/secret")) {
		char id[SESSION_ID_LENGTH + 1]; // +1 to detect over-length IDs.
		connection.GetRequestData(WebRequestDataType_Cookie, "id", id, sizeof(id));
		PrintToServer(">>> id = %s", id);
		
		if ((strlen(id) + 1) != SESSION_ID_LENGTH) {
			return connection.QueueResponse(WebStatus_Found, loginRedirectResponse);
		}
		
		DataPack sessionPack;
		if (!sessions.GetValue(id, sessionPack)) {
			return connection.QueueResponse(WebStatus_Found, loginRedirectResponse);
		}
		
		sessionPack.Reset();
		
		char ip[WEB_CLIENT_ADDRESS_LENGTH];
		connection.GetClientAddress(ip, sizeof(ip));
		
		char session_ip[WEB_CLIENT_ADDRESS_LENGTH];
		sessionPack.ReadString(session_ip, sizeof(session_ip));
		
		if (strcmp(ip, session_ip) != 0) {
			delete sessionPack;
			sessions.Remove(id);
			return connection.QueueResponse(WebStatus_Found, loginRedirectResponse);
		}
		
		char steamid[32];
		sessionPack.ReadString(steamid, sizeof(steamid));
		
		AdminId admin = FindAdminByIdentity(AUTHMETHOD_STEAM, steamid);
		
		if (admin == INVALID_ADMIN_ID) {
			return connection.QueueResponse(WebStatus_Forbidden, forbiddenResponse);
		}
		
		if (!CheckAccess(admin, "sm_rcon", ADMFLAG_RCON)) {
			return connection.QueueResponse(WebStatus_Forbidden, forbiddenResponse);
		}
	
		return connection.QueueResponse(WebStatus_OK, topSecretResponse);
	}

	return connection.QueueResponse(WebStatus_NotFound, notFoundResponse);
}
