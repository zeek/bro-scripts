@load mime

#
# An email attachment analyzer.
#
# It inspects the CONTENT-TYPE header of a MIME attachment. It reports
# potentially problematic mime types and names of sensitive file extensions.
#

module Email;

export {
    redef enum Notice += {
        SensitiveMIMEType,      # Sensitive MIME type.
        SensitiveExtension,     # Sensitive file extension.
    };

    # Directory in which email attachments are stored.
    const attachment_dir = "mime-attachments" &redef;

    # Whether attachments with sensitive MIME types should be stored.
    const store_sensitive_mime_types = T &redef;

    # Whether attachments with sensitive file extensions should be stored.
    const store_sensitive_extensions = T &redef;

    # Sensitive MIME types that raise a notice.
    const sensitive_mime_types = 
        /application\/.*/   #/application\/(x-dosexec|msword|pdf)/ 
      | /document\/.*/
      | /image\/.*/
      | /video\/.*/
      &redef;

    # The list of sensitve file extensions that raise a notice.
    const sensitive_extensions = 
      # Office documents.
        /[pP][dD][fF]$/
      | /[dD][oO][cC][xX]?$/
      | /[xX][lL][sS]$/
      | /[pP][pP][sStT]$/
      # Executables.
      | /[eE][xX][eE]$/
      | /[cC][oO][mM]$/
      | /[bB][aA][tT]$/
      # Comprehensive list of archive and compression extensions.
      | /[aA]([cC][eE]|[rR][cC]|[lL][zZ]|[rR][jJ])?$/
      | /[bB][zZ]2$/
      | /[cC][pP][iI][oO]$/
      | /[dD]([dD]|[gG][zZ]|[mM][gG])$/
      | /[cC]([aA][bB]|[pP][tT])$/
      | /[fF]$/
      | /[gG][cChH][aA]$/
      | /[gG]?[zZ]$/
      | /[hH]([aA]|[kK][iI])$/
      | /[iI][cC][eE]$/
      | /[jJ]$/
      | /[kK][gG][bB]$/
      | /[lL([bB][rR]$/
      | /[lL][zZ]([mMzZ][aA]|[aA][hH]|[oO]|[xX])?$/
      | /[pP][aA]([rR][tT][iI][mM][gG]|[qQ]([0-9a-zA-Z])*)$/
      | /[pP]([eE][aA]|[iI][mMtT])$/
      | /[qQ][dD][aA]$/
      | /[rR]([aA][rR]|[kK])$/
      | /[sS][fF][aA][rR][kK]$/
      | /[sS]([dD][aA]|[eE][aAnN]|[fF][xX]|[iI][tT][xX]?|[qQ][xX])$/
      | /[sS]?7[zZ]$/
      | /([tT]|[sS][hH])?[aA][rR]$/
      | /[tT][gGlL][zZ]$/
      | /[uU][hH][aA]$/
      | /[wW][iI][mM]$/
      | /[xX][aA][rR]$/
      | /[zZ]([iI][pP]|[oO][oO]|[zZ])$/
      &redef; 

    # Type for an email attachment.
    type attachment: record
    {
        id: count;
        mime_session: count;
        mime_type: string;
        filename: string;
        fh: file;
    };
}

# Unique attachment identifier. 
global attachment_id: count = 0;

# Attachments by MIME connection ID.
global attachments: table[conn_id] of attachment;

# Create a new attachment record.
function new_attachment(session: MIME::mime_session_info, mime_type: string,
        filename: string) : attachment
{
    local a: attachment;
    a$id = ++attachment_id;
    a$mime_session = session$id;
    a$mime_type = mime_type;
    a$filename = filename;

    return a;
}

# Invoked for every CONTENT-TYPE header.
function mime_header_content_type(session: MIME::mime_session_info, 
    name: string, arg: string)
{
    local mime_type = sub(arg, /;.*$/, "");
    local filename: string;
    local store_attachment = F;

    if (sensitive_mime_types in mime_type)
    {
        NOTICE([$note=SensitiveMIMEType, 
                $id=session$connection_id,
                $msg=fmt("sensitive MIME type in email attachment (%s)",
                    mime_type),
                $tag=fmt("%d", session$id)
                ]);

        if (store_sensitive_mime_types)
        {
            store_attachment = T;
            filename = gsub(mime_type, /\//, "_");
        }
    }

    if (/[nN][aA][mM][eE]=/ in arg)
    {
        filename = sub(arg, /^.*[nN][aA][mM][eE]=/, "");
        filename = gsub(filename, /\"/, "");  # Strip ".

        if (sensitive_extensions in filename)
            NOTICE([$note=SensitiveExtension, 
                    $id=session$connection_id,
                    $msg=fmt("sensitive extension in email attachment (%s)",
                        filename),
                    $filename=filename,
                    $tag=fmt("%d", session$id)
                    ]);

        store_attachment = T;
    }

    if (store_attachment)
    {
        local a = new_attachment(session, mime_type, filename);
        attachments[session$connection_id] = a;

        filename = fmt("%s/%d-%s", attachment_dir, a$id, filename);
        a$fh = open(filename);
    }
}

redef MIME::mime_header_handler += { 
    ["CONTENT-TYPE"] = mime_header_content_type
};

# Close attachment and evict state.
event mime_end_entity(c: connection)
{
    local id = c$id;
    if (id !in attachments)
        return;

    local a = attachments[id];
    close(a$fh);
    delete attachments[id];
}

# Dispatch mime segment data to the corresponding attachment.
event mime_segment_data(c: connection, length: count, data: string)
{
    local id = c$id;
    if (id !in attachments)
        return;

    local a = attachments[id];
    write_file(a$fh, data);
}

event bro_init()
{
    if (store_sensitive_mime_types || store_sensitive_extensions)
        mkdir(attachment_dir);
}
