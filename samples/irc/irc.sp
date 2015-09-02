#include <conplex>

#pragma semicolon 1
#pragma newdecls required

#define	MSG_PEEK 0x2

char serverhost[64] = "SRCDS";
char servertime[64] = "Unknown";
char serverversion[64] = "Unknown";

StringMap commands;
ArrayList sockets;
StringMap nicknames;

enum IRCCommand
{
	Command_Invalid,
	Command_PASS,
	Command_NICK,
	Command_USER,
	Command_QUIT,
	Command_PING,
	//Command_PONG,
	Command_PRIVMSG,
	Command_NOTICE,
	//Command_JOIN,
	//Command_PART,
};

public void OnPluginStart()
{
	int serverip = FindConVar("hostip").IntValue;
	int serverport = FindConVar("hostport").IntValue;
	FormatEx(serverhost, sizeof(serverhost), "%d.%d.%d.%d:%d", (serverip >> 24) & 0xFF, (serverip >> 16) & 0xFF, (serverip >> 8) & 0xFF, serverip & 0xFF, serverport);

	FormatTime(servertime, sizeof(servertime), "%a %d %b %Y at %H:%M:%S %Z", GetTime() - RoundFloat(GetEngineTime()));
	TrimString(servertime);

	File versionFile = OpenFile("steam.inf", "rb");
	if (versionFile) {
		char line[64];
		while (versionFile.ReadLine(line, sizeof(line))) {
			int split = FindCharInString(line, '=');
			if (split == -1) {
				continue;
			}

			line[split] = '\0';
			TrimString(line);

			if (strcmp(line, "ServerVersion") != 0) {
				continue;
			}

			TrimString(line[split + 1]);
			strcopy(serverversion, sizeof(serverversion), line[split + 1]);
		}

		delete versionFile;
	}

	commands = new StringMap();

	commands.SetValue("PASS", Command_PASS);
	commands.SetValue("NICK", Command_NICK);
	commands.SetValue("USER", Command_USER);
	commands.SetValue("QUIT", Command_QUIT);
	commands.SetValue("PING", Command_PING);
	//commands.SetValue("PONG", Command_PONG);
	commands.SetValue("PRIVMSG", Command_PRIVMSG);
	commands.SetValue("NOTICE", Command_NOTICE);
	//commands.SetValue("JOIN", Command_JOIN);
	//commands.SetValue("PART", Command_PART);

	sockets = new ArrayList();
	nicknames = new StringMap();

	Conplex_RegisterProtocol("IRC", IRCProtocolDetector, IRCProtocolHandler);
}

bool NormalizeNickname(char[] nickname) {
	int length = strlen(nickname);
	for (int i = 0; i < length; ++i) {
		char c = nickname[i];

		if (c >= 'A' && c <= 'Z') {
			nickname[i] = (c + 32);
			continue;
		}

		if (c >= 'a' && c <= 'z') {
			continue;
		}

		if (i == 0) {
			nickname[0] = '\0';
			return false;
		}

		if (c >= '0' && c <= '9') {
			continue;
		}

		if (c >= '[' && c <= '^') {
			nickname[i] = (c + 32);
			continue;
		}

		if (c == '-' || c == '_' || c == '`') {
			continue;
		}

		if (c >= '{' && c <= '~') {
			continue;
		}

		nickname[0] = '\0';
		return false;
	}

	return true;
}

public void OnGameFrame()
{
	int socketCount = sockets.Length;
	for (int i = (socketCount - 1); i >= 0; --i) {
		// This is an absolutely awful way to parse network data.
		ConplexSocket socket = sockets.Get(i);
		StringMap socketData = socket.Context;

		// Need this early for cleanup on kill.
		char nickname[MAX_NAME_LENGTH] = "*";
		socketData.GetString("nickname", nickname, sizeof(nickname));

		char username[MAX_NAME_LENGTH];
		socketData.GetString("username", username, sizeof(username));

		char hostname[46];
		socketData.GetString("hostname", hostname, sizeof(hostname));

		char prefix[128];
		FormatEx(prefix, sizeof(prefix), "%s!~%s@%s", nickname, username, hostname);

		bool registered;
		socketData.GetValue("registered", registered);

		char buffer[513];
		int ret = socket.Receive(buffer, sizeof(buffer) - 1, MSG_PEEK);
		//PrintToServer(">>> %d = %s", ret, buffer);

		if (ret == -2) {
			// TODO: Send PING requests.

			continue;
		}

		if (ret == -1) {
			PrintToServer("IRC Receive Error!!!");
		}

		int length = FindCharInString(buffer, '\n');

		if (length == -1) {
			if (ret > 0) {
				PrintToServer(">>> BAD COMMAND FROM CLIENT");
			}

			// TODO: Send quit message to interested parties.

			if (nickname[0] != '*') {
				nicknames.Remove(nickname);
			}

			if (registered) {
				int targets = sockets.Length;
				for (int n = 0; n < targets; ++n) {
					ConplexSocket target = sockets.Get(n);
					StringMap targetData = target.Context;

					bool targetRegistered;
					targetData.GetValue("registered", targetRegistered);

					if (!targetRegistered) {
						continue;
					}

					ret = FormatEx(buffer, sizeof(buffer), ":%s QUIT :EOF from client.\r\n", prefix);
					target.Send(buffer, ret, 0);
				}
			}

			delete socketData;
			delete socket;
			sockets.Erase(i);
			continue;
		}

		if (length > 0 && buffer[length - 1] == '\r') {
			length--;
		}

		char[] line = new char[length + 1];
		strcopy(line, length + 1, buffer);
		PrintToServer(">>> IRC LINE: \"%s\"", line);

		if (buffer[length] == '\r') {
			length++;
		}

		// Dispose of the data we have parsed. Like I said, awful.
		socket.Receive(buffer, length + 1, 0);

		if (line[0] == '\0') {
			continue;
		}

		int offset = 0;

		// Trim leading whitespace.
		while (line[offset] == ' ') {
			offset++;
		}

		// Skip the prefix.
		if (line[offset] == ':') {
			offset += 1 + FindCharInString(line[offset], ' ');
		}

		// Trim leading whitespace again.
		while (line[offset] == ' ') {
			offset++;
		}

		int extendedParamPosition = offset;
		bool hasExtendedParam = false;

		while ((ret = FindCharInString(line[extendedParamPosition], ':')) != -1) {
			extendedParamPosition += ret + 1;
			if (line[extendedParamPosition - 2] == ' ') {
				hasExtendedParam = true;
				break;
			}
		}

		if (hasExtendedParam) {
			// Truncate the line so we can explode the other params.
			line[extendedParamPosition - 1] = '\0';
		}

		// Collapse whitespace in the command and parameter list.
		while (ReplaceString(line[offset], (length - offset) + 1, "  ", " ") > 0) {
			// Empty.
		}

		// Trim trailing whitespace.
		int commandAndParamsLength = strlen(line[offset]);
		if (line[(offset + commandAndParamsLength) - 1] == ' ') {
			commandAndParamsLength--;
			line[offset + commandAndParamsLength] = '\0';
		}

		int commandLength = FindCharInString(line[offset], ' ');
		bool hasParams = (commandLength != -1);
		if (!hasParams) {
			commandLength = commandAndParamsLength;
		}

		char[] command = new char[commandLength + 1];
		for (int n = 0; n < commandLength; ++n) {
			char c = line[offset + n];

			if (c >= 'a' && c <= 'z') {
				c -= 32;
			}

			command[n] = c;
		}

		char params[15][513];
		int numParams = hasParams ? ExplodeString(line[offset + commandLength + 1], " ", params, sizeof(params), sizeof(params[])) : 0;

		if (hasExtendedParam && numParams < sizeof(params)) {
			// Fill in the extend param.
			strcopy(params[numParams], sizeof(params[]), line[extendedParamPosition]);
			numParams++;
		}

		PrintToServer("> COMMAND: %s", command);

		for (int n = 0; n < numParams; ++n) {
			PrintToServer("> PARAM %d: %s", n, params[n]);
		}

		IRCCommand ircCommand = Command_Invalid;
		commands.GetValue(command, ircCommand);

		if (!registered) {
			switch (ircCommand) {
				case Command_Invalid: {
					// Do nothing.
				}
				case Command_PASS: {
					// Do nothing. Passwords not supported.
				}
				case Command_NICK: {
					if (numParams < 1) {
						ret = FormatEx(buffer, sizeof(buffer), ":%s 431 %s :No nickname given\r\n", serverhost, nickname);
						socket.Send(buffer, ret, 0);
						break;
					}

					if (nickname[0] != '*' && strcmp(nickname, params[0]) == 0) {
						break;
					}

					char normalized[MAX_NAME_LENGTH];
					strcopy(normalized, sizeof(normalized), params[0]);

					if (!NormalizeNickname(normalized)) {
						ret = FormatEx(buffer, sizeof(buffer), ":%s 432 %s %s :Erroneus nickname\r\n", serverhost, nickname, params[0]);
						socket.Send(buffer, ret, 0);
						break;
					}

					ConplexSocket otherSocket;
					if (nicknames.GetValue(normalized, otherSocket) && otherSocket != socket) {
						ret = FormatEx(buffer, sizeof(buffer), ":%s 433 %s %s :Nickname is already in use\r\n", serverhost, nickname, params[0]);
						socket.Send(buffer, ret, 0);
						break;
					}

					if (nickname[0] != '*') {
						char normalizedNickname[MAX_NAME_LENGTH];
						strcopy(normalizedNickname, sizeof(normalizedNickname), nickname);
						NormalizeNickname(normalizedNickname);

						if (strcmp(normalizedNickname, normalized) != 0) {
							nicknames.Remove(normalizedNickname);
							nicknames.SetValue(normalized, socket);
						}
					} else {
						nicknames.SetValue(normalized, socket);
					}

					strcopy(nickname, sizeof(nickname), params[0]);
					socketData.SetString("nickname", nickname);
				}
				case Command_USER: {
					if (numParams < 4) {
						ret = FormatEx(buffer, sizeof(buffer), ":%s 461 %s USER :Not enough parameters\r\n", serverhost, nickname);
						socket.Send(buffer, ret, 0);
						break;
					}

					strcopy(username, sizeof(username), params[0]);
					socketData.SetString("username", username);

					socketData.SetString("realname", params[3]);
				}
				case Command_QUIT: {
					if (nickname[0] != '*') {
						nicknames.Remove(nickname);
					}

					delete socketData;
					delete socket;
					sockets.Erase(i);
				}
				default: {
					ret = FormatEx(buffer, sizeof(buffer), ":%s 451 %s :You have not registered\r\n", serverhost, nickname);
					socket.Send(buffer, ret, 0);
				}
			}

			registered = ((nickname[0] != '*') && (username[0] != '\0'));

			if (!registered) {
				continue;
			}

			FormatEx(prefix, sizeof(prefix), "%s!~%s@%s", nickname, username, hostname);

			socketData.SetValue("registered", true);

			ret = FormatEx(buffer, sizeof(buffer), ":%s 001 %s :Welcome to the SRCDS IRCd, %s\r\n", serverhost, nickname, prefix);
			socket.Send(buffer, ret, 0);

			ret = FormatEx(buffer, sizeof(buffer), ":%s 002 %s :Your host is %s, running version %s\r\n", serverhost, nickname, serverhost, serverversion);
			socket.Send(buffer, ret, 0);

			ret = FormatEx(buffer, sizeof(buffer), ":%s 003 %s :This server was created %s\r\n", serverhost, nickname, servertime);
			socket.Send(buffer, ret, 0);

			ret = FormatEx(buffer, sizeof(buffer), ":%s 004 %s %s %s\r\n", serverhost, nickname, serverhost, serverversion);
			socket.Send(buffer, ret, 0);

			ret = FormatEx(buffer, sizeof(buffer), ":%s 005 %s CASEMAPPING=rfc1459 CHANNELLEN=64 CHANTYPES=# NICKLEN=32 PREFIX TARGMAX=PRIVMSG:20,NOTICE:20 CHANLIMIT=#: CHANMODES=,,, KICKLEN=128 TOPICLEN=256 NETWORK=%s :are supported by this server\r\n", serverhost, nickname, serverhost);
			socket.Send(buffer, ret, 0);

			ret = FormatEx(buffer, sizeof(buffer), ":%s 422 %s :MOTD File is missing\r\n", serverhost, nickname);
			socket.Send(buffer, ret, 0);

			ret = FormatEx(buffer, sizeof(buffer), ":%s JOIN #chat\r\n", prefix);
			socket.Send(buffer, ret, 0);

			ret = FormatEx(buffer, sizeof(buffer), ":%s 332 %s #chat :SRCDS General Chat\r\n", serverhost, nickname);
			socket.Send(buffer, ret, 0);

			int targets = sockets.Length;
			for (int n = 0; n < targets; ++n) {
				ConplexSocket target = sockets.Get(n);
				StringMap targetData = target.Context;

				bool targetRegistered;
				targetData.GetValue("registered", targetRegistered);

				if (!targetRegistered) {
					continue;
				}

				char targetNickname[MAX_NAME_LENGTH];
				targetData.GetString("nickname", targetNickname, sizeof(targetNickname));

				// Already sent this up above.
				if (target != socket) {
					ret = FormatEx(buffer, sizeof(buffer), ":%s JOIN #chat\r\n", prefix);
					target.Send(buffer, ret, 0);
				}

				// TODO: Bunch these.
				ret = FormatEx(buffer, sizeof(buffer), ":%s 353 %s = #chat :%s\r\n", serverhost, nickname, targetNickname);
				socket.Send(buffer, ret, 0);
			}

			ret = FormatEx(buffer, sizeof(buffer), ":%s 366 %s #chat :End of /NAMES list.\r\n", serverhost, nickname);
			socket.Send(buffer, ret, 0);

			continue;
		}

		switch (ircCommand) {
			case Command_Invalid: {
				ret = FormatEx(buffer, sizeof(buffer), ":%s 421 %s %s :Unknown command\r\n", serverhost, nickname, command);
				socket.Send(buffer, ret, 0);
			}
			case Command_PASS: {
				ret = FormatEx(buffer, sizeof(buffer), ":%s 462 %s :You may not reregister\r\n", serverhost, nickname);
				socket.Send(buffer, ret, 0);
			}
			case Command_NICK: {
				if (numParams < 1) {
					ret = FormatEx(buffer, sizeof(buffer), ":%s 431 %s :No nickname given\r\n", serverhost, nickname);
					socket.Send(buffer, ret, 0);
					break;
				}

				if (strcmp(nickname, params[0]) == 0) {
					break;
				}

				char normalized[MAX_NAME_LENGTH];
				strcopy(normalized, sizeof(normalized), params[0]);

				if (!NormalizeNickname(normalized)) {
					ret = FormatEx(buffer, sizeof(buffer), ":%s 432 %s %s :Erroneus nickname\r\n", serverhost, nickname, params[0]);
					socket.Send(buffer, ret, 0);
					break;
				}

				ConplexSocket otherSocket;
				if (nicknames.GetValue(normalized, otherSocket) && otherSocket != socket) {
					ret = FormatEx(buffer, sizeof(buffer), ":%s 433 %s %s :Nickname is already in use\r\n", serverhost, nickname, params[0]);
					socket.Send(buffer, ret, 0);
					break;
				}

				char normalizedNickname[MAX_NAME_LENGTH];
				strcopy(normalizedNickname, sizeof(normalizedNickname), nickname);
				NormalizeNickname(normalizedNickname);

				if (strcmp(normalizedNickname, normalized) != 0) {
					nicknames.Remove(normalizedNickname);
					nicknames.SetValue(normalized, socket);
				}

				socketData.SetString("nickname", params[0]);

				int targets = sockets.Length;
				for (int n = 0; n < targets; ++n) {
					ConplexSocket target = sockets.Get(n);
					StringMap targetData = target.Context;

					bool targetRegistered;
					targetData.GetValue("registered", targetRegistered);

					if (!targetRegistered) {
						continue;
					}

					ret = FormatEx(buffer, sizeof(buffer), ":%s NICK :%s\r\n", prefix, params[0]);
					target.Send(buffer, ret, 0);
				}
			}
			case Command_USER: {
				ret = FormatEx(buffer, sizeof(buffer), ":%s 462 %s :You may not reregister\r\n", serverhost, nickname);
				socket.Send(buffer, ret, 0);
			}
			case Command_QUIT: {
				char message[129] = "Disconnect by user.";

				if (numParams >= 1) {
					strcopy(message, sizeof(message), params[0]);
				}

				int targets = sockets.Length;
				for (int n = 0; n < targets; ++n) {
					ConplexSocket target = sockets.Get(n);
					StringMap targetData = target.Context;

					bool targetRegistered;
					targetData.GetValue("registered", targetRegistered);

					if (!targetRegistered) {
						continue;
					}

					ret = FormatEx(buffer, sizeof(buffer), ":%s QUIT :%s\r\n", prefix, message);
					target.Send(buffer, ret, 0);
				}

				nicknames.Remove(nickname);

				delete socketData;
				delete socket;
				sockets.Erase(i);
			}
			case Command_PING: {
				if (numParams < 1) {
					ret = FormatEx(buffer, sizeof(buffer), ":%s 409 %s :No origin specified\r\n", serverhost, nickname);
					socket.Send(buffer, ret, 0);
					break;
				}

				ret = FormatEx(buffer, sizeof(buffer), ":%s PONG %s :%s\r\n", serverhost, serverhost, params[0]);
				socket.Send(buffer, ret, 0);
			}
			case Command_PRIVMSG, Command_NOTICE: {
				if (numParams < 1) {
					if (ircCommand != Command_NOTICE) {
						ret = FormatEx(buffer, sizeof(buffer), ":%s 411 %s :No recipient given (%s)\r\n", serverhost, nickname, command);
						socket.Send(buffer, ret, 0);
					}

					break;
				}

				if (numParams < 2 || params[1][0] == '\0') {
					if (ircCommand != Command_NOTICE) {
						ret = FormatEx(buffer, sizeof(buffer), ":%s 412 %s :No text to send\r\n", serverhost, nickname);
						socket.Send(buffer, ret, 0);
					}

					break;
				}

				// TODO: Channels.

				char targets[20][MAX_NAME_LENGTH];
				int count = ExplodeString(params[0], ",", targets, sizeof(targets), sizeof(targets[]));
				for (int n = 0; n < count; ++n) {
					if (targets[n][0] != '#') {
						ConplexSocket recipient;

						char normalized[MAX_NAME_LENGTH];
						strcopy(normalized, sizeof(normalized), targets[n]);

						if (!NormalizeNickname(normalized) || !nicknames.GetValue(normalized, recipient)) {
							if (ircCommand != Command_NOTICE) {
								ret = FormatEx(buffer, sizeof(buffer), ":%s 412 %s %s :No such nick\r\n", serverhost, nickname, targets[n]);
								socket.Send(buffer, ret, 0);
							}

							continue;
						}

						ret = FormatEx(buffer, sizeof(buffer), ":%s %s %s :%s\r\n", prefix, command, targets[n], params[1]);
						recipient.Send(buffer, ret, 0);

						continue;
					}

					if (strcmp(targets[n], "#chat") != 0) {
						ret = FormatEx(buffer, sizeof(buffer), ":%s 412 %s %s :No such channel\r\n", serverhost, nickname, targets[n]);
						socket.Send(buffer, ret, 0);
						continue;
					}

					int recipientCount = sockets.Length;
					for (int c = 0; c < recipientCount; ++c) {
						ConplexSocket recipient = sockets.Get(c);

						if (recipient == socket) {
							continue;
						}

						StringMap recipientData = recipient.Context;

						bool recipientRegistered;
						recipientData.GetValue("registered", recipientRegistered);

						if (!recipientRegistered) {
							continue;
						}

						ret = FormatEx(buffer, sizeof(buffer), ":%s %s %s :%s\r\n", prefix, command, targets[n], params[1]);
						recipient.Send(buffer, ret, 0);
					}
				}
			}
			default: {
				PrintToServer(">>> Missing IRC command handler for: %s", command);
			}
		}
	}
}

public ConplexProtocolDetectionState IRCProtocolDetector(const char[] id, const char[] data, int length)
{
	if (length <= 0) return ConplexProtocolDetection_NeedMoreData;

	switch (data[0]) {
		case 'C':
			if (length <= 1) return ConplexProtocolDetection_NeedMoreData;
			else if (data[1] != 'A') return ConplexProtocolDetection_NoMatch;
			else if (length <= 2) return ConplexProtocolDetection_NeedMoreData;
			else if (data[2] != 'P') return ConplexProtocolDetection_NoMatch;
			else if (length <= 3) return ConplexProtocolDetection_NeedMoreData;
			else if (data[3] != ' ' && data[3] != '\r' && data[3] != '\n') return ConplexProtocolDetection_NoMatch;
		case 'N':
			if (length <= 1) return ConplexProtocolDetection_NeedMoreData;
			else if (data[1] != 'I') return ConplexProtocolDetection_NoMatch;
			else if (length <= 2) return ConplexProtocolDetection_NeedMoreData;
			else if (data[2] != 'C') return ConplexProtocolDetection_NoMatch;
			else if (length <= 3) return ConplexProtocolDetection_NeedMoreData;
			else if (data[3] != 'K') return ConplexProtocolDetection_NoMatch;
			else if (length <= 4) return ConplexProtocolDetection_NeedMoreData;
			else if (data[4] != ' ' && data[4] != '\r' && data[4] != '\n') return ConplexProtocolDetection_NoMatch;
		case 'U':
			if (length <= 1) return ConplexProtocolDetection_NeedMoreData;
			else if (data[1] != 'S') return ConplexProtocolDetection_NoMatch;
			else if (length <= 2) return ConplexProtocolDetection_NeedMoreData;
			else if (data[2] != 'E') return ConplexProtocolDetection_NoMatch;
			else if (length <= 3) return ConplexProtocolDetection_NeedMoreData;
			else if (data[3] != 'R') return ConplexProtocolDetection_NoMatch;
			else if (length <= 4) return ConplexProtocolDetection_NeedMoreData;
			else if (data[4] != ' ' && data[4] != '\r' && data[4] != '\n') return ConplexProtocolDetection_NoMatch;
		case 'P':
			if (length <= 1) return ConplexProtocolDetection_NeedMoreData;
			else if (data[1] != 'A') return ConplexProtocolDetection_NoMatch;
			else if (length <= 2) return ConplexProtocolDetection_NeedMoreData;
			else if (data[2] != 'S') return ConplexProtocolDetection_NoMatch;
			else if (length <= 3) return ConplexProtocolDetection_NeedMoreData;
			else if (data[3] != 'S') return ConplexProtocolDetection_NoMatch;
			else if (length <= 4) return ConplexProtocolDetection_NeedMoreData;
			else if (data[4] != ' ' && data[4] != '\r' && data[4] != '\n') return ConplexProtocolDetection_NoMatch;
		case 'S':
			if (length <= 1) return ConplexProtocolDetection_NeedMoreData;
			else if (data[1] != 'T') return ConplexProtocolDetection_NoMatch;
			else if (length <= 2) return ConplexProtocolDetection_NeedMoreData;
			else if (data[2] != 'A') return ConplexProtocolDetection_NoMatch;
			else if (length <= 3) return ConplexProtocolDetection_NeedMoreData;
			else if (data[3] != 'R') return ConplexProtocolDetection_NoMatch;
			else if (length <= 4) return ConplexProtocolDetection_NeedMoreData;
			else if (data[4] != 'T') return ConplexProtocolDetection_NoMatch;
			else if (length <= 5) return ConplexProtocolDetection_NeedMoreData;
			else if (data[5] != 'T') return ConplexProtocolDetection_NoMatch;
			else if (length <= 6) return ConplexProtocolDetection_NeedMoreData;
			else if (data[6] != 'L') return ConplexProtocolDetection_NoMatch;
			else if (length <= 7) return ConplexProtocolDetection_NeedMoreData;
			else if (data[7] != 'S') return ConplexProtocolDetection_NoMatch;
			else if (length <= 8) return ConplexProtocolDetection_NeedMoreData;
			else if (data[8] != '\r' && data[8] != '\n') return ConplexProtocolDetection_NoMatch;
		case 'Q':
			if (length <= 1) return ConplexProtocolDetection_NeedMoreData;
			else if (data[1] != 'U') return ConplexProtocolDetection_NoMatch;
			else if (length <= 2) return ConplexProtocolDetection_NeedMoreData;
			else if (data[2] != 'I') return ConplexProtocolDetection_NoMatch;
			else if (length <= 3) return ConplexProtocolDetection_NeedMoreData;
			else if (data[3] != 'T') return ConplexProtocolDetection_NoMatch;
			else if (length <= 4) return ConplexProtocolDetection_NeedMoreData;
			else if (data[4] != ' ' && data[4] != '\r' && data[4] != '\n') return ConplexProtocolDetection_NoMatch;
		default:
			return ConplexProtocolDetection_NoMatch;
	}

	return ConplexProtocolDetection_Match;
}

public bool IRCProtocolHandler(const char[] id, ConplexSocket socket, const char[] address)
{
	StringMap socketData = new StringMap();
	socketData.SetString("hostname", address);

	socket.Context = socketData;
	sockets.Push(socket);

	return true;
}
