#if defined _webcon_included
#endinput
#endif
#define _webcon_included

//const char WebMethod_Connect[] = "CONNECT";
//const char WebMethod_Delete[] = "DELETE";
//const char WebMethod_Get[] = "GET";
//const char WebMethod_Head[] = "HEAD";
//const char WebMethod_Options[] = "OPTIONS";
//const char WebMethod_Post[] = "POST";
//const char WebMethod_Put[] = "PUT";
//const char WebMethod_Patch[] = "PATCH";
//const char WebMethod_Trace[] = "TRACE";

#define WebMethod_Connect "CONNECT"
#define WebMethod_Delete "DELETE"
#define WebMethod_Get "GET"
#define WebMethod_Head "HEAD"
#define WebMethod_Options "OPTIONS"
#define WebMethod_Post "POST"
#define WebMethod_Put "PUT"
#define WebMethod_Patch "PATCH"
#define WebMethod_Trace "TRACE"

enum WebStatus
{
	WebStatus_Continue = 100,
	WebStatus_SwitchingProtocols = 101,
	WebStatus_Processing = 102,

	WebStatus_OK = 200,
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

#define WebHeader_Accept "Accept"
#define WebHeader_AcceptCharset "Accept-Charset"
#define WebHeader_AcceptEncoding "Accept-Encoding"
#define WebHeader_AcceptLanguage "Accept-Language"
#define WebHeader_AcceptRanges "Accept-Ranges"
#define WebHeader_Age "Age"
#define WebHeader_Allow "Allow"
#define WebHeader_Authorization "Authorization"
#define WebHeader_CacheControl "Cache-Control"
#define WebHeader_Connection "Connection"
#define WebHeader_ContentEncoding "Content-Encoding"
#define WebHeader_ContentLanguage "Content-Language"
#define WebHeader_ContentLength "Content-Length"
#define WebHeader_ContentLocation "Content-Location"
#define WebHeader_ContentMD5  "Content-MD5"
#define WebHeader_ContentRange "Content-Range"
#define WebHeader_ContentType "Content-Type"
#define WebHeader_Cookie "Cookie"
#define WebHeader_Date "Date"
#define WebHeader_ETag "ETag"
#define WebHeader_Expect "Expect"
#define WebHeader_Expires "Expires"
#define WebHeader_From "From"
#define WebHeader_Host "Host"
#define WebHeader_IfMatch "If-Match"
#define WebHeader_IfModifiedSince "If-Modified-Since"
#define WebHeader_IfNoneMatch "If-None-Match"
#define WebHeader_IfRange "If-Range"
#define WebHeader_IfUnmodifiedSince "If-Unmodified-Since"
#define WebHeader_LastModified "Last-Modified"
#define WebHeader_Location "Location"
#define WebHeader_MaxForwards "Max-Forwards"
#define WebHeader_Pragma "Pragma"
#define WebHeader_ProxyAuthenticate "Proxy-Authenticate"
#define WebHeader_ProxyAuthorization "Proxy-Authorization"
#define WebHeader_Range "Range"
#define WebHeader_Referer "Referer"
#define WebHeader_RetryAfter "Retry-After"
#define WebHeader_Server "Server"
#define WebHeader_SetCookie "Set-Cookie"
#define WebHeader_SetCookie2 "Set-Cookie2"
#define WebHeader_TE "TE"
#define WebHeader_Trailer "Trailer"
#define WebHeader_TransferEncoding "Transfer-Encoding"
#define WebHeader_Upgrade "Upgrade"
#define WebHeader_UserAgent "User-Agent"
#define WebHeader_Vary "Vary"
#define WebHeader_Via "Via"
#define WebHeader_Warning "Warning"
#define WebHeader_WWWAuthenticate "WWW-Authenticate"
#define WebHeader_AccessControlAllowOrigin "Access-Control-Allow-Origin"

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
