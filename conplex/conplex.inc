#if defined _conplex_included
#endinput
#endif
#define _conplex_included

enum ConplexProtocolDetectionState
{
	ConplexProtocolDetection_NoMatch,
	ConplexProtocolDetection_NeedMoreData,
	ConplexProtocolDetection_Match,
}

typedef ConplexProtocolDetector = function ConplexProtocolDetectionState (const char[] id, const char[] data, int length);
typedef ConplexProtocolHandler = function bool (const char[] id, int socket, const char[] address);

native bool Conplex_RegisterProtocol(const char[] id, ConplexProtocolDetector detector, ConplexProtocolHandler handler);

public Extension __ext_Conplex = 
{
	name = "Conplex",
	file = "conplex.ext",
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
}
