#if defined _webcon_included
#endinput
#endif
#define _webcon_included

enum WebStatus
{
	WebStatus_Continue = 100,
	WebStatus_SwitchingProtocols = 101,
	WebStatus_Processing = 102,

	WebStatus_Ok = 200,
	WebStatus_Created = 201,
	WebStatus_Accepted = 202,
	WebStatus_NonAuthoritativeInformation = 203,
	WebStatus_NoContent = 204,
	WebStatus_ResetContent = 205,
	WebStatus_PartialContent = 206,
	WebStatus_MultiStatus = 207,

	WebStatus_MultipleChoices = 300,
	WebStatus_MovedPermanently = 301,
	WebStatus_Found = 302,
	WebStatus_SeeOther = 303,
	WebStatus_NotModified = 304,
	WebStatus_UseProxy = 305,
	WebStatus_SwitchProxy = 306,
	WebStatus_TemporaryRedirect = 307,

	WebStatus_BadRequest = 400,
	WebStatus_Unauthorized = 401,
	WebStatus_PaymentRequired = 402,
	WebStatus_Forbidden = 403,
	WebStatus_NotFound = 404,
	WebStatus_MethodNotAllowed = 405,
	WebStatus_NotAcceptable = 406,
	WebStatus_ProxyAuthenticationRequired = 407,
	WebStatus_RequestTimeout = 408,
	WebStatus_Conflict = 409,
	WebStatus_Gone = 410,
	WebStatus_LengthRequired = 411,
	WebStatus_PreconditionFailed = 412,
	WebStatus_RequestEntityTooLarge = 413,
	WebStatus_RequestUriTooLong = 414,
	WebStatus_UnsupportedMediaType = 415,
	WebStatus_RequestedRangeNotSatisfiable = 416,
	WebStatus_ExpectationFailed = 417,
	WebStatus_UnprocessableEntity = 422,
	WebStatus_Locked = 423,
	WebStatus_FailedDependency = 424,
	WebStatus_UnorderedCollection = 425,
	WebStatus_UpgradeRequired = 426,
	WebStatus_NoResponse = 444,
	WebStatus_RetryWith = 449,
	WebStatus_BlockedByWindowsParentalControls = 450,
	WebStatus_UnavailableForLegalReasons = 451,

	WebStatus_InternalServerError = 500,
	WebStatus_NotImplemented = 501,
	WebStatus_BadGateway = 502,
	WebStatus_ServiceUnavailable = 503,
	WebStatus_GatewayTimeout = 504,
	WebStatus_HttpVersionNotSupported = 505,
	WebStatus_VariantAlsoNegotiates = 506,
	WebStatus_InsufficientStorage = 507,
	WebStatus_BandwidthLimitExceeded = 509,
	WebStatus_NotExtended = 510,
}

methodmap WebResponse < Handle
{
	public native WebResponse(const char[] content);
};

methodmap WebConnection < Handle
{
	public native bool QueueResponse(WebStatus status, WebResponse response);
};

forward Action OnWebRequest(WebConnection connection, const char[] url, const char[] method);

public Extension __ext_Webcon = 
{
	name = "Webcon",
	file = "webcon.ext",
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
