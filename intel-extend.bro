##! Give users the ability to add information to their intelligence
##! hits log.

@load base/frameworks/intel

module IntelExtend;

export {
	redef enum Log::ID += { LOG };

	## An event that can be handled if you wish to extend the 
	## intel_extend log.  The log line is stored in the `info`
	## argument and can be inspected and modified.
	##
	## Additional arguments for the intel_extend log can be 
	## added by extending the Intel::Info record and handling 
	## the IntelExtend::match event at a priority higher than -5.
	global match: event(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]);
}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Intel::Info]);
	Log::disable_stream(Intel::LOG);
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item]) &priority=5
	{
	print "match!";
	local info = Intel::Info($ts=network_time(), $seen=s);

	if ( s?$f )
		{
		if ( s$f?$conns && |s$f$conns| == 1 )
			{
			for ( cid in s$f$conns )
				s$conn = s$f$conns[cid];
			}

		if ( ! info?$fuid )
			info$fuid = s$f$id;

		if ( ! info?$file_mime_type && s$f?$mime_type )
			info$file_mime_type = s$f$mime_type;

		if ( ! info?$file_desc )
			info$file_desc = Files::describe(s$f);
		}

	if ( s?$conn )
		{
		info$uid = s$conn$uid;
		info$id  = s$conn$id;
		}

	for ( item in items )
		add info$sources[item$meta$source];

	event IntelExtend::match(info, s, items);
	}

event IntelExtend::match(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item]) &priority=-5
	{
	Log::write(IntelExtend::LOG, info);
	}