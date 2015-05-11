#include <sourcemod>
#include <sdktools>
#include <webcon>

#pragma semicolon 1
#pragma newdecls required

#define BASE_PATH "configs/web/players/"

WebResponse indexResponse;
WebResponse backgroundResponse;
WebResponse classesResponse;
WebResponse fontResponse;
WebResponse notFoundResponse;

int lastDataGeneration;
WebResponse dataResponse;

bool isTF2;

public void OnPluginStart()
{
	isTF2 = (GetEngineVersion() == Engine_TF2);

	if (!Web_RegisterRequestHandler("players", OnWebRequest, "Player List")) {
		SetFailState("Failed to register request handler.");
	}

	char path[PLATFORM_MAX_PATH];

	BuildPath(Path_SM, path, sizeof(path), BASE_PATH ... "index.html");
	indexResponse = new WebFileResponse(path);
	indexResponse.AddHeader(WebHeader_ContentType, "text/html");

	BuildPath(Path_SM, path, sizeof(path), BASE_PATH ... "background.jpg");
	backgroundResponse = new WebFileResponse(path);
	backgroundResponse.AddHeader(WebHeader_ContentType, "image/jpeg");
	backgroundResponse.AddHeader(WebHeader_CacheControl, "public, max-age=2629740");

	BuildPath(Path_SM, path, sizeof(path), BASE_PATH ... "classes.png");
	classesResponse = new WebFileResponse(path);
	classesResponse.AddHeader(WebHeader_ContentType, "image/png");
	classesResponse.AddHeader(WebHeader_CacheControl, "public, max-age=2629740");

	BuildPath(Path_SM, path, sizeof(path), BASE_PATH ... "tf2.ttf");
	fontResponse = new WebFileResponse(path);
	fontResponse.AddHeader(WebHeader_ContentType, "application/x-font-ttf");
	fontResponse.AddHeader(WebHeader_CacheControl, "public, max-age=2629740");

	BuildPath(Path_SM, path, sizeof(path), BASE_PATH ... "notfound.html");
	notFoundResponse = new WebFileResponse(path);
	notFoundResponse.AddHeader(WebHeader_ContentType, "text/html");
}

int WriteByte(char[] buffer, int length, int value)
{
	if (length < 1) {
		return 0;
	}

	buffer[0] = value & 0xFF;

	return 1;
}

int WriteShort(char[] buffer, int length, int value)
{
	if (length < 2) {
		return 0;
	}

	buffer[0] = value & 0xFF;
	buffer[1] = (value >> 8) & 0xFF;

	return 2;
}

int WriteInt(char[] buffer, int length, int value)
{
	if (length < 4) {
		return 0;
	}

	buffer[0] = value & 0xFF;
	buffer[1] = (value >> 8) & 0xFF;
	buffer[2] = (value >> 16) & 0xFF;
	buffer[3] = (value >> 24) & 0xFF;

	return 4;
}

public bool OnWebRequest(WebConnection connection, const char[] method, const char[] url)
{
	if (StrEqual(url, "/data")) {
		int time = GetTime();
		if (dataResponse != null && (time - lastDataGeneration) < 5) {
			return connection.QueueResponse(WebStatus_OK, dataResponse);
		}

		int resourceEnt = GetPlayerResourceEntity();
		if (resourceEnt == -1) {
			return false;
		}

		char buffer[4 + 4 + 1 + (65 * (1 + 32 + 1 + 1 + 2 + 4 + 2))];
		int length = 0;

		length += WriteInt(buffer[length], sizeof(buffer) - length, GetTeamScore(3));
		length += WriteInt(buffer[length], sizeof(buffer) - length, GetTeamScore(2));

		int numPlayersPosition = length;
		length += WriteByte(buffer[length], sizeof(buffer) - length, 0);

		int numPlayers = 0;
		for (int i = 1; i <= MaxClients; ++i) {
			if (!IsClientInGame(i)) {
				continue;
			}

			int team = GetClientTeam(i);

			if (team == 0) {
				continue;
			}

			numPlayers++;

			length += WriteByte(buffer[length], sizeof(buffer) - length, team);
			length += 1 + FormatEx(buffer[length], sizeof(buffer) - length, "%N", i);

			if (team == 1) {
				continue;
			}

			bool bot = IsFakeClient(i);

			length += WriteByte(buffer[length], sizeof(buffer) - length, bot);

			int tfclass = 0;
			if (isTF2) {
				tfclass = GetEntProp(i, Prop_Send, "m_iClass");
			}
			length += WriteByte(buffer[length], sizeof(buffer) - length, tfclass);

			length += WriteShort(buffer[length], sizeof(buffer) - length, GetEntProp(resourceEnt, Prop_Send, "m_iTotalScore", _, i));

			if (bot) {
				continue;
			}

			length += WriteInt(buffer[length], sizeof(buffer) - length, GetSteamAccountID(i, false));
			length += WriteShort(buffer[length], sizeof(buffer) - length, GetEntProp(resourceEnt, Prop_Send, "m_iPing", _, i));
		}

		WriteByte(buffer[numPlayersPosition], sizeof(buffer) - numPlayersPosition, numPlayers);

		if (length > sizeof(buffer)) {
			ThrowError("Buffer size mismatch: %d > %d", length, sizeof(buffer));
			return false;
		}

		lastDataGeneration = time;

		delete dataResponse;
		dataResponse = new WebBinaryResponse(buffer, length);
		dataResponse.AddHeader(WebHeader_ContentType, "application/octet-stream");
		dataResponse.AddHeader(WebHeader_CacheControl, "public, max-age=5");

		return connection.QueueResponse(WebStatus_OK, dataResponse);
	}

	if (StrEqual(url, "/")) {
		return connection.QueueResponse(WebStatus_OK, indexResponse);
	}

	if (StrEqual(url, "/background.jpg")) {
		return connection.QueueResponse(WebStatus_OK, backgroundResponse);
	}

	if (StrEqual(url, "/classes.png")) {
		return connection.QueueResponse(WebStatus_OK, classesResponse);
	}

	if (StrEqual(url, "/tf2.ttf")) {
		return connection.QueueResponse(WebStatus_OK, fontResponse);
	}

	return connection.QueueResponse(WebStatus_NotFound, notFoundResponse);
}
