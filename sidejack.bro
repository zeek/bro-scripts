@load notice
@load http-request
@load http-reply

module HTTP;

export
{
    redef enum Notice +=
    {
        SessionCookieReuse,     # Cookie reuse by a different user agent
        SessionCookieRoamed,    # Cookie reuse by a roaming user
        Sidejacking             # Cookie reuse by an attacker
    };

    # Control how to define a user. If the flag is set, a user is defined
    # solely by its IP address and otherwise defined by the (IP, user agent)
    # pair. It can make sense to deactive this flag in a deployment upstream of
    # a NAT. However, false positivies can then arise when the same user sends
    # the same session cookie from multiple user agents.
    const user_is_ip = T &redef;

    # Whether to keep track of multiple IP addresses for the same host. This
    # can reduce false positives for roaming clients that leave and join the
    # network under a new IP address, yet use the same session within the
    # cookie expiration interval. It makes only sense to set this flag when Bro
    # actually sees DHCP or ARP traffic.
    const use_aliasing = F &redef;

    # Whether to restrict the analysis only to the known services listed below.
    const known_services_only = T &redef;

    # Time after which a seen cookie is forgotten.
    const cookie_expiration = 1 hr &redef;

    type ServiceInfo: record
    {
        desc: string;                # Service description.
        url: pattern;                # URL pattern matched against Host header.
        keys: set[string] &optional; # Cookie keys that define the user session.
        pat: pattern &optional;      # Cookie keys pattern, instead of a set.
    };

    # Known session cookie definitions (from Firesheep handlers).
    #
    # FIXME: Ideally we use a 'vector of ServiceInfo' type here, but there is
    # a bug in Bro that results in a type clash when constructing records with
    # optional attributes inside a vector definition (see #485). A workaround
    # is to use a table instead, yet this introduces a redundancy of key and
    # $desc.  When this bug is fixed, we can simply remove any line consisting
    # of
    #
    #   ["KEY"] =
    #
    # to make the service defintion redundancy-free (and more readable).
    const services: table[string] of ServiceInfo =
    {
    ["Amazon"] =
        [$desc="Amazon", $url=/amazon.com/, $keys=set("x-main")],
    ["Basecamp"] =
        [$desc="Basecamp", $url=/basecamphq.com/,
            $keys=set("_basecamp_session", "session_token")],
    ["bit.ly"] =
        [$desc="bit.ly", $url=/bit.ly/, $keys=set("user")],
    ["Cisco"] =
        [$desc="Cisco", $url=/cisco.com/, $keys=set("SMIDENTITY")],
    ["Cnet"] =
        [$desc="CNET", $url=/cnet.com/, $keys=set("urs_sessionId")],
    ["Enom"] =
        [$desc="Enom", $url=/enom.com/,
            $keys=set("OatmealCookie", "EmailAddress")],
    ["Evernote"] =
        [$desc="Evernote", $url=/evernote.com/, $keys=set("auth")],
    ["Facebook"] =
        [$desc="Facebook", $url=/facebook.com/,
        $keys=set("datr", "c_user", "lu", "sct")],
    ["Flickr"] =
        [$desc="Flickr", $url=/flickr.com/, $keys=set("cookie_session")],
    ["Fiverr"] =
        [$desc="Fiverr", $url=/fiverr.com/, $keys=set("_fiverr_session")],
    ["Foursquare"] =
        [$desc="Foursquare", $url=/foursquare.com/,
            $keys=set("ext_id", "XSESSIONID")],
    ["Google"] =
        [$desc="Google", $url=/google.com/,
            $keys=set("NID", "SID", "HSID", "PREF")],
    ["Gowalla"] =
        [$desc="Gowalla", $url=/gowalla.com/, $keys=set("__utma")],
    ["Hacker News"] =
        [$desc="Hacker News", $url=/news.ycombinator.com/, $keys=set("user")],
    ["Harvest"] =
        [$desc="Harvest", $url=/harvestapp.com/, $keys=set("_harvest_sess")],
    ["LinkedIn"] =
        [$desc="LinkedIn", $url=/linkedin.com/, $keys=set("bcookie")],
    ["Pivotal Tracker"] =
        [$desc="Pivotal Tracker", $url=/pivotaltracker.com\/dashboard/,
            $keys=set("tracker_session")],
    ["Posterous"] =
        [$desc="Posterous", $url=/.*/, $keys=set("_sharebymail_session_id")],
    ["NY Times"] =
        [$desc="NY Times", $url=/nytimes.com/, $keys=set("NYT-s", "nyt-d")],
    ["Reddit"] =
        [$desc="Reddit", $url=/reddit.com/, $keys=set("reddit_session")],
    ["ShutterStock"] =
        [$desc="ShutterStock", $url=/shutterstock.com/, $keys=set("ssssidd")],
    ["StackOverflow"] =
        [$desc="StackOverflow", $url=/stackoverflow.com/,
            $keys=set("usr", "gauthed")],
    ["tumblr"] =
        [$desc="tumblr", $url=/tumblr.com/, $keys=set("pfp")],
    ["Twitter"] =
        [$desc="Twitter", $url=/twitter.com/,
            $keys=set("_twitter_sess", "auth_token")],
    ["Vimeo"] =
        [$desc="Vimeo", $url=/vimeo.com/, $keys=set("vimeo")],
    ["Yahoo"] =
        [$desc="Yahoo", $url=/yahoo.com/, $keys=set("T", "Y")],
    ["Yelp"] =
        [$desc="Yelp", $url=/yelp.com/, $keys=set("__utma")],
    ["Windows Live"] =
        [$desc="Windows Live", $url=/live.com/,
            $keys=set("MSPProf", "MSPAuth", "RPSTAuth", "NAP")],
    ["Wordpress"] =
        [$desc="Wordpress", $url=/wordpress.com/, $pat=/wordpress_[0-9a-fA-F]+/]
    } &redef;
}

@ifdef(use_aliasing)
@load roam
@endif

# Per-cookie state.
type CookieContext: record
{
    mac: string;            # MAC address of the user.
    client: addr;           # IP address of the user.
    user_agent: string;     # User-Agent header.
    last_seen: time;        # Last time we saw the cookie from this user.
    last_http_id: string;   # Last seen HTTP session ID.
    cookie: string;         # The session cookie, as seen the last time.
};

# Map cookies to their contextual state.
global cookies: table[string] of CookieContext &read_expire = cookie_expiration;

# Hijacked sessions that have already been reported.
global hijacking_reported: set[string, string] &read_expire = cookie_expiration;

# Reported cookie reuse.
global reuse_reported: set[string, string] &read_expire = cookie_expiration;

# Create a unique user session identifier based on the relevant cookie keys.
# Return the empty string if the sessionization does not succeed.
function sessionize(cookie: string, info: ServiceInfo) : string
{
    local id = "";
    local fields = split(cookie, /; /);

    if (info?$keys)
    {
        local matches: table[string] of string;
        for (i in fields)
        {
            local s = split1(fields[i], /=/);
            if (s[1] in info$keys)
                matches[s[1]] = s[2];
        }

        if (|matches| == |info$keys|)
            for (key in info$keys)
            {
                if (id != "")
                    id += "; ";
                id += key + "=" + matches[key];
            }
    }

    if (info?$pat)
    {
        for (i in fields)
        {
            s = split1(fields[i], /=/);
            if (s[1] == info$pat)
                id += id == "" ? fields[i] : cat("; ", fields[i]);
        }
    }

    return id;
}

function is_aliased(client: addr, ctx: CookieContext) : bool
{
    if (client in Roam::ip_to_mac)
    {
        local mac = Roam::ip_to_mac[client];
        if (mac == ctx$mac && mac in Roam::mac_to_ip
            && client in Roam::mac_to_ip[mac])
            return T;
    }

    return F;
}

function update_cookie_context(ctx: CookieContext, cookie: string, id: string)
{
    ctx$cookie = cookie;
    ctx$last_seen = network_time();
    ctx$last_http_id = id;
    if (use_aliasing && ctx$client in Roam::ip_to_mac)
        ctx$mac = Roam::ip_to_mac[ctx$client];
}

function format_address(a: addr) : string
{
    if (use_aliasing && a in Roam::ip_to_mac)
        return fmt("%s[%s]", a, Roam::ip_to_mac[a]);
    else
        return fmt("%s", a);
}

function report_session_reuse(c: connection, user_agent: string,
        http_id: string, service: string, ctx: CookieContext)
{
    if ([ctx$cookie, user_agent] in reuse_reported)
        return;

    add reuse_reported[ctx$cookie, user_agent];

    local client = c$id$orig_h;
    local attacker = format_address(client);
    local victim = format_address(ctx$client);
    NOTICE([$note=SessionCookieReuse, $conn=c,
            $user=fmt("%s '%s'", client, user_agent),
            $msg=fmt("%s (%s) reused %s session %s in user agent '%s', where previous user agent was '%s' and last seen at %s via cookie %s",
                attacker, http_id, service, ctx$last_http_id, user_agent,
                ctx$user_agent, ctx$last_seen, ctx$cookie)]);
}

function report_session_roamed(c: connection, user_agent: string,
        http_id: string, service: string, ctx: CookieContext)
{
    local client = c$id$orig_h;
    local roamer = format_address(client);
    NOTICE([$note=SessionCookieRoamed, $conn=c,
            $user=fmt("%s '%s'", client, user_agent),
            $msg=fmt("%s (%s) roamed %s session %s in user agent '%s' and last seen at %s via cookie %s",
                roamer, http_id, service, ctx$last_http_id, user_agent,
                ctx$last_seen, ctx$cookie)]);
}

# Create a unique user ID based on the notion of user.
function make_user(client: addr, user_agent: string) : string
{
    return user_is_ip ? fmt("%s", client) : fmt("%s '%s'", client, user_agent);
}

function report_sidejacking(c: connection, user_agent: string,
        http_id: string, service: string, ctx: CookieContext)
{
    local client = c$id$orig_h;
    local user = make_user(client, user_agent);

    if ([ctx$cookie, user] in hijacking_reported)
        return;

    add hijacking_reported[ctx$cookie, user];

    local attacker = format_address(client);
    local victim = format_address(ctx$client);
    NOTICE([$note=Sidejacking, $conn=c,
            $user=fmt("%s '%s'", attacker, user_agent),
            $msg=fmt("%s (%s) @ '%s' hijacked %s session (%s) of %s @ '%s' last seen at %s via cookie %s",
                attacker, http_id, user_agent, service, ctx$last_http_id,
                victim, ctx$user_agent, ctx$last_seen, ctx$cookie)]);
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
    if (! is_orig)
        return;

    local cookie = "";
    local user_agent = "";
    local host = "";
    for (i in hlist)
    {
        local hdr = hlist[i]$name;
        local value = hlist[i]$value;
        if (hdr == "COOKIE")
            cookie = value;
        else if (hdr == "USER-AGENT")
            user_agent = value;
        else if (hdr == "HOST")
            host = to_lower(value);
    }

    if (cookie == "")
        return;

    local service = host;
    local session_cookie = "";
    if (host != "")
        for (s in services)
        {
            local info = services[s];
            if (info$url in host)
            {
                session_cookie = sessionize(cookie, info);
                if (session_cookie != "")
                {
                    service = info$desc;
                    break;
                }
            }
        }

    if (session_cookie == "")
    {
        if (known_services_only)
            return;

        session_cookie = cookie;
    }
    else
        session_cookie = fmt("subset %s", session_cookie);

    local client = c$id$orig_h;
    local user = make_user(client, user_agent);
    local http_id = lookup_http_session(c)$id;

    if (session_cookie !in cookies)
    {
        local mac = "";
        if (use_aliasing && client in Roam::ip_to_mac)
            mac = Roam::ip_to_mac[client];

        cookies[session_cookie] =
        [
            $client=client,
            $user_agent=user_agent,
            $last_seen=network_time(),
            $last_http_id=http_id,
            $cookie=session_cookie,
            $mac=mac
        ];

        # Do not convict a cookie's first use.
        add hijacking_reported[session_cookie, user];
        add reuse_reported[session_cookie, user_agent];
    }

    local ctx = cookies[session_cookie];

    if (user_is_ip)
    {
        if (client == ctx$client)
        {
            if (user_agent != ctx$user_agent)
            {
                report_session_reuse(c, user_agent, http_id, service, ctx);

                # Uncommenting this will have the effect of reversing the
                # current and previous user agent, allowing for another notice
                # when the previous user agent appears again.
                #ctx$user_agent = user_agent;
            }

            update_cookie_context(ctx, session_cookie, http_id);
        }
        else if (user_agent != ctx$user_agent)
        {
            report_sidejacking(c, user_agent, http_id, service, ctx);
        }
        else if (use_aliasing)
        {
            if (is_aliased(client, ctx))
            {
                update_cookie_context(ctx, session_cookie, http_id);
                report_session_roamed(c, user_agent, http_id, service, ctx);

            }
            else
                report_sidejacking(c, user_agent, http_id, service, ctx);
        }
    }
    else if (client == ctx$client && user_agent == ctx$user_agent)
        update_cookie_context(ctx, session_cookie, http_id);
    else
        report_sidejacking(c, user_agent, http_id, service, ctx);
}
