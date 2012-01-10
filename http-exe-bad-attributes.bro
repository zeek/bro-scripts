##! Detect bad executable downloaded by watching for attributes of the 
##! connection or request.
##!
##! Authors: Justin Azoff and Seth Hall

@load base/protocols/http

module HTTPExecBadAttributes;

export {
	redef enum Notice::Type += {
		## Indicates detection of a Windows executable downloaded over HTTP
		## with one or more of a number of attributes.
		Detected
	};
	
	## Pattern matching URLs that tend to be malicious if they return a 
	## Windows executable.
	const bad_exec_urls = 
	    /php\.adv=/
	  | /^http:\/\/[^\/]c[oxz]\.cc\//
	  | /^http:\/\/www1/
	  | /^http:\/\/[0-9]{1,3}\.[0-9]{1,3}.*\/index\.php\?[^=]+=[^=]+$/ #try to match http://1.2.3.4/index.php?foo=bar
	  | /load\.php/ &redef;
	
	## Pattern matching user-agents that will tend to be bad to see downloading
	## Windows executables.
	const bad_user_agents = /Java\/1/ &redef;
}

event log_http(rec: HTTP::Info)
	{
	if ( ! rec?$mime_type || rec$mime_type != "application/x-dosexec" )
	    return;
	
	local reason = "";
	local value = "";
	local url = HTTP::build_url_http(rec);
	if ( bad_user_agents in rec$user_agent )
		{
		reason = "user-agent";
		value = rec$user_agent;
		}
	else if ( bad_exec_urls in url )
		{
		reason = "url";
		value = url;
		}
	
	if ( reason != "" )
		{
		NOTICE([$note=Detected,
		        $src=rec$id$orig_h,
		        $msg=fmt("%s downloaded a Windows executable and the connection had a potentially bad %s.", rec$id$orig_h, reason),
		        $sub=value,
		        $identifier=cat(rec$id$orig_h,reason,value)]);
		}
}