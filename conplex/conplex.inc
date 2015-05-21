#if defined _conplex_included
#endinput
#endif
#define _conplex_included

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
