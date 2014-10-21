##! A script for handling URLs in SMTP traffic.  This script does 
##! two things.  It logs URLs discovered in SMTP traffic.  It 
##! also records them in a bloomfilter and looks for them to be
##! visited through HTTP requests.  
##!
##! Authors: Aashish Sharma <asharma@lbl.gov>
##!          Seth Hall <seth@icir.org>


@load base/utils/urls

module SMTP_URL;

export {
	redef enum Log::ID += { Links_LOG };

	type Info: record {
		## When the email was seen.
		ts:   time    &log;
		## Unique ID for the connection.
		uid:  string  &log;
		## Connection details.
		id:   conn_id &log;
		## Depth of the email into the SMTP exchange.
		trans_depth: count &log;
		## The host field extracted from the discovered URL.
		host: string  &log &optional;
		## URL that was discovered.
		url:  string  &log &optional;
	};

	redef enum Notice::Type += {
		## A link discovered in an email appears to have been clicked.
		Link_in_Email_Clicked,

		## An email was seen in email that matched the pattern in 
		## `SMTP_URL::suspicious_urls`
		Suspicious_URL,

		## Certain file extensions in email links can be watched for
		## with the pattern in `SMTP_URL::suspicious_file_extensions`
		Suspicious_File_Extension,

		## URL with a dotted IP address seen in an email.
		Dotted_URL
	};
	
	const suspicious_file_extensions = /\.([rR][aA][rR]|[eE][xX][eE]|[zZ][iI][pP])$/ &redef;
	const suspicious_urls = /googledocs?/ &redef;

	const ignore_file_types = /\.([gG][iI][fF]|[pP][nN][gG]|[jJ][pP][gG]|[xX][mM][lL]|[jJ][pP][eE]?[gG]|[cC][sS][sS])$/ &redef;

	## The following 
	const ignore_mail_originators: set[subnet] = { } &redef;
	const ignore_mailfroms = /bro@|alerts|reports/ &redef;
	const ignore_notification_emails = {"alerts@example.com", "notices@example.com"} &redef;
	const ignore_site_links = /http:\/\/.*\.example\.com\/|http:\/\/.*\.example\.net/ &redef;
}

# The bloomfilter that stores all of the links seen in email.
global mail_links_bf: opaque of bloomfilter;

redef record connection += {
	smtp_url: Info &optional;
};

event bro_init() &priority=5
	{
	# initialize the bloomfilter
	mail_links_bf = bloomfilter_basic_init(0.00000001, 10000000, "SMTP_URL");

	Log::create_stream(Links_LOG, [$columns=Info]);
	}

function extract_host(name: string): string
	{
	local split_on_slash = split(name, /\//);
	return split_on_slash[3];
	}

function log_smtp_urls(c: connection, url: string)
	{
	c$smtp_url = Info($ts   = c$smtp$ts,
	                  $uid  = c$uid,
	                  $id   = c$id,
	                  $trans_depth = c$smtp$trans_depth,
	                  $host = extract_host(url),
	                  $url  = url);

	Log::write(SMTP_URL::Links_LOG, c$smtp_url);
	}

event SMTP_URL::email_data(f: fa_file, data: string)
	{
	# Grab the connection.
	local c: connection;
	for ( cid in f$conns )
		{
		c = f$conns[cid];
		break;
		}
	
	if( c$smtp?$mailfrom && ignore_mailfroms in c$smtp$mailfrom )
		{
		return;
		}

	if ( c$smtp?$to )
		{
		for ( to in c$smtp$to )
			{
			if ( to in ignore_notification_emails )
				return;
			}
		}

	local mail_info = Files::describe(f);
	local urls = find_all_urls(data);
	for ( link in urls )
		{
		#local link =  sub(a,/(http|https):\/\//,"");
		#local _bf_lookup = bloomfilter_lookup(mail_links_bf, link);

		#if (link !in mail_links_bf && ignore_file_types !in link )
		#if ((_bf_lookup ==  0) && ignore_file_types !in link )
		
		if ( ignore_file_types !in link )
			{
			bloomfilter_add(mail_links_bf, link);
			log_smtp_urls(c, link);
			
			if ( suspicious_file_extensions in link )
				{
				NOTICE([$note = Suspicious_File_Extension,
				        $msg  = fmt("Suspicious file extension embedded in URL %s from  %s", link, c$id$orig_h),
				        $sub  = mail_info,
				        $conn = c]);
				}
			
			if ( suspicious_urls in link )
				{
				NOTICE([$note = Suspicious_URL,
				        $msg  = fmt("Suspicious text embedded in URL %s from  %s", link, c$smtp$uid),
				        $sub  = mail_info,
				        $conn = c]);
				}
			
			if ( /([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}.*/ in link )
				{ 
				NOTICE([$note = Dotted_URL,
				        $msg  = fmt("Embedded IP address in URL %s from  %s", link, c$id$orig_h),
				        $sub  = mail_info,
				        $conn = c]);
				}

		}
	}
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f$source == "SMTP" && c?$smtp && 
	     c$id$orig_h !in ignore_mail_originators )
		{
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=SMTP_URL::email_data]);
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-3
	{
	local str = HTTP::build_url_http(c$http);
	if ( bloomfilter_lookup(SMTP_URL::mail_links_bf, str) > 0 &&
	     ignore_file_types !in str &&
	     ignore_site_links !in str)
		{
		NOTICE([$note=SMTP_URL::Link_in_Email_Clicked,
		        $msg=fmt("URL %s ", str),
		        $conn=c]);
		}
	}


