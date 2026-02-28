/* packet-mcp.c
 * Dissector for Model Context Protocol (MCP)
 * 
 * MCP is a JSON-RPC 2.0 based protocol for AI <-> tool communication
 * Typically runs over HTTP with SSE for streaming
 * 
 * Author: AI Assistant (小乐宝)
 * License: GPLv2+
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/strutil.h>
#include <epan/json_stream.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/strtoi.h>

#define MCP_NAME "Model Context Protocol (MCP)"
#define MCP_NAME_SHORT "MCP"
#define TCP_PORT_MCP 3000

/* Protocol handle */
static int proto_mcp = -1;

/* HF (Header Field) indices */
static int hf_mcp_type = -1;
static int hf_mcp_method = -1;
static int hf_mcp_jsonrpc_version = -1;
static int hf_mcp_id = -1;
static int hf_mcp_id_num = -1;
static int hf_mcp_params = -1;
static int hf_mcp_result = -1;
static int hf_mcp_error = -1;
static int hf_mcp_error_code = -1;
static int hf_mcp_error_message = -1;
static int hf_mcp_error_data = -1;
static int hf_mcp_sse_event = -1;
static int hf_mcp_sse_data = -1;
static int hf_mcp_sse_id = -1;
static int hf_mcp_sse_retry = -1;
static int hf_mcp_tool_name = -1;
static int hf_mcp_tool_input = -1;
static int hf_mcp_resource_uri = -1;
static int hf_mcp_resource_content = -1;
static int hf_mcp_prompt_name = -1;
static int hf_mcp_prompt_args = -1;

/* Tree variables */
static gint ett_mcp = -1;
static gint ett_mcp_message = -1;
static gint ett_mcp_params = -1;
static gint ett_mcp_result = -1;
static gint ett_mcp_error = -1;
static gint ett_mcp_sse = -1;
static gint ett_mcp_tools = -1;
static gint ett_mcp_resources = -1;
static gint ett_mcp_prompts = -1;

/* Port preference */
static guint mcp_tcp_port = TCP_PORT_MCP;

/* Known MCP methods */
static const value_string mcp_method_vals[] = {
    /* Tools */
    {0, "tools/list"},
    {1, "tools/call"},
    {2, "resources/list"},
    {3, "resources/read"},
    {4, "resources/subscribe"},
    {5, "resources/unsubscribe"},
    {6, "prompt/list"},
    {7, "prompt/get"},
    {8, "roots/list"},
    {9, "sampling/createMessage"},
    {10, "initialize"},
    {11, "initialized"},
    {0, NULL}
};

/* JSON-RPC error codes */
static const value_string jsonrpc_error_codes[] = {
    {-32700, "Parse error"},
    {-32600, "Invalid Request"},
    {-32601, "Method not found"},
    {-32602, "Invalid params"},
    {-32603, "Internal error"},
    {-32000, "Server error"},
    {0, NULL}
};

/* Forward declarations */
static void dissect_mcp_jsonrpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len);
static void dissect_mcp_sse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len);
static gint dissect_mcp_find_method(tvbuff_t *tvb, int offset, int len);
static void dissect_mcp_params(tvbuff_t *tvb, proto_tree *tree, int offset, int len);
static void dissect_mcp_result(tvbuff_t *tvb, proto_tree *tree, int offset, int len);

/*
 * Check if this is MCP traffic
 */
static gboolean is_mcp_content(const guchar *data, int len)
{
    /* Look for MCP/JSON-RPC indicators */
    if (len < 10) return FALSE;
    
    /* Check for JSON-RPC 2.0 */
    if (strstr((const char*)data, "\"jsonrpc\":") || 
        strstr((const char*)data, "\"jsonrpc\" :")) {
        return TRUE;
    }
    
    /* Check for MCP-specific methods */
    if (strstr((const char*)data, "\"tools/list\"") ||
        strstr((const char*)data, "\"tools/call\"") ||
        strstr((const char*)data, "\"resources/list\"") ||
        strstr((const char*)data, "\"prompt/get\"") ||
        strstr((const char*)data, "\"initialize\"")) {
        return TRUE;
    }
    
    /* Check for SSE format */
    if (strstr((const char*)data, "event:") &&
        strstr((const char*)data, "data:")) {
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Find a string in tvb and return its value
 */
static gint find_json_string(tvbuff_t *tvb, int offset, int len, const gchar *key, gchar **value)
{
    const guchar *data;
    gchar *key_pos;
    gchar *colon_pos;
    gchar *quote_start;
    gchar *quote_end;
    int key_len;
    
    data = tvb_get_ptr(tvb, offset, len);
    if (!data) return -1;
    
    key_len = (int)strlen(key);
    key_pos = (gchar*)g_strstr_len((const gchar*)data, len, key);
    if (!key_pos) return -1;
    
    colon_pos = key_pos + key_len;
    /* Skip whitespace and colon */
    while (colon_pos < (gchar*)data + len && *colon_pos != ':') {
        colon_pos++;
    }
    if (*colon_pos != ':') return -1;
    colon_pos++;
    
    /* Skip whitespace */
    while (colon_pos < (gchar*)data + len && *colon_pos == ' ') colon_pos++;
    
    if (*colon_pos != '"') return -1;
    quote_start = colon_pos + 1;
    quote_end = quote_start;
    while (quote_end < (gchar*)data + len && *quote_end != '"') {
        quote_end++;
    }
    
    if (quote_end > quote_start) {
        *value = (gchar*)g_malloc(quote_end - quote_start + 1);
        tvb_get_nstringz0(tvb, offset + (quote_start - (gchar*)data), 
                          quote_end - quote_start, *value);
        return (int)(quote_start - (gchar*)data);
    }
    
    return -1;
}

/*
 * Find numeric value
 */
static gint find_json_number(tvbuff_t *tvb, int offset, int len, const gchar *key, gint64 *value)
{
    const guchar *data;
    gchar *key_pos;
    gchar *colon_pos;
    gchar *num_start;
    gchar *num_end;
    gchar num_buf[32];
    int key_len;
    
    data = tvb_get_ptr(tvb, offset, len);
    if (!data) return -1;
    
    key_len = (int)strlen(key);
    key_pos = (gchar*)g_strstr_len((const gchar*)data, len, key);
    if (!key_pos) return -1;
    
    colon_pos = key_pos + key_len;
    while (colon_pos < (gchar*)data + len && *colon_pos != ':') colon_pos++;
    if (*colon_pos != ':') return -1;
    colon_pos++;
    
    while (colon_pos < (gchar*)data + len && *colon_pos == ' ') colon_pos++;
    
    num_start = colon_pos;
    num_end = num_start;
    while (num_end < (gchar*)data + len && 
           (*num_end == '-' || *num_end == '.' || 
            (*num_end >= '0' && *num_end <= '9'))) {
        num_end++;
    }
    
    if (num_end > num_start) {
        int num_len = num_end - num_start;
        if (num_len >= (int)sizeof(num_buf)) num_len = sizeof(num_buf) - 1;
        memcpy(num_buf, num_start, num_len);
        num_buf[num_len] = '\0';
        *value = g_ascii_strtoll(num_buf, NULL, 10);
        return (int)(num_start - (gchar*)data);
    }
    
    return -1;
}

/*
 * Main dissector function
 */
static int dissect_mcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    int len;
    const guchar *data;
    proto_item *ti, *ti_msg;
    proto_tree *mcp_tree, *msg_tree;
    gchar *method = NULL;
    gint64 id = 0;
    gboolean has_id = FALSE;
    
    len = tvb_captured_length(tvb);
    if (len == 0) return 0;
    
    data = tvb_get_ptr(tvb, offset, len);
    if (!data) return 0;
    
    /* Check if this is MCP traffic */
    if (!is_mcp_content(data, len)) {
        return 0;
    }
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, MCP_NAME_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);
    
    /* Create protocol tree */
    ti = proto_tree_add_item(tree, proto_mcp, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
    mcp_tree = proto_item_add_subtree(ti, ett_mcp);
    
    /* Detect if it's SSE or JSON-RPC */
    if (strstr((const char*)data, "event:")) {
        col_add_str(pinfo->cinfo, COL_INFO, "MCP Server-Sent Events");
        dissect_mcp_sse(tvb, pinfo, mcp_tree, offset, len);
    } else {
        col_add_str(pinfo->cinfo, COL_INFO, "MCP JSON-RPC");
        dissect_mcp_jsonrpc(tvb, pinfo, mcp_tree, offset, len);
    }
    
    return tvb_captured_length(tvb);
}

/*
 * Dissect JSON-RPC messages
 */
static void dissect_mcp_jsonrpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len)
{
    proto_item *ti_msg;
    proto_tree *msg_tree;
    gchar *method = NULL;
    gint64 id = 0;
    gboolean has_id = FALSE;
    const guchar *data;
    
    data = tvb_get_ptr(tvb, offset, len);
    if (!data) return;
    
    /* Create message subtree */
    ti_msg = proto_tree_add_item(tree, hf_mcp_type, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
    msg_tree = proto_item_add_subtree(ti_msg, ett_mcp_message);
    
    /* Look for jsonrpc version */
    if (strstr((const char*)data, "\"jsonrpc\":") || 
        strstr((const char*)data, "\"jsonrpc\" :")) {
        proto_tree_add_string(msg_tree, hf_mcp_jsonrpc_version, tvb, offset, 7, "2.0");
    }
    
    /* Look for method */
    if (find_json_string(tvb, offset, len, "\"method\"", &method) > 0 && method) {
        proto_tree_add_string(msg_tree, hf_mcp_method, tvb, offset, 
                            strlen(method), method);
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", method);
        g_free(method);
    }
    
    /* Look for id (can be string, number, or null) */
    if (find_json_number(tvb, offset, len, "\"id\"", &id) > 0) {
        has_id = TRUE;
        proto_tree_add_int64(msg_tree, hf_mcp_id_num, tvb, offset, id);
    }
    
    /* Look for params */
    if (g_strstr_len((const gchar*)data, len, "\"params\"")) {
        /* Find params section */
        dissect_mcp_params(tvb, msg_tree, offset, len);
    }
    
    /* Look for result */
    if (g_strstr_len((const gchar*)data, len, "\"result\"")) {
        dissect_mcp_result(tvb, msg_tree, offset, len);
    }
    
    /* Look for error */
    if (g_strstr_len((const gchar*)data, len, "\"error\"")) {
        proto_item *ti_err;
        proto_tree *err_tree;
        gint64 error_code = 0;
        gchar *error_msg = NULL;
        
        ti_err = proto_tree_add_item(msg_tree, hf_mcp_error, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
        err_tree = proto_item_add_subtree(ti_err, ett_mcp_error);
        
        if (find_json_number(tvb, offset, len, "\"code\"", &error_code) > 0) {
            proto_tree_add_int(err_tree, hf_mcp_error_code, tvb, offset, (gint)error_code);
        }
        
        if (find_json_string(tvb, offset, len, "\"message\"", &error_msg) > 0 && error_msg) {
            proto_tree_add_string(err_tree, hf_mcp_error_message, tvb, offset, 
                                strlen(error_msg), error_msg);
            g_free(error_msg);
        }
    }
}

/*
 * Dissect SSE (Server-Sent Events)
 */
static void dissect_mcp_sse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len)
{
    proto_item *ti_sse;
    proto_tree *sse_tree;
    const guchar *data;
    gchar *line, *colon;
    int line_start, line_end;
    
    ti_sse = proto_tree_add_item(tree, hf_mcp_sse_event, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
    sse_tree = proto_item_add_subtree(ti_sse, ett_mcp_sse);
    
    data = tvb_get_ptr(tvb, offset, len);
    if (!data) return;
    
    /* Parse SSE lines */
    line_start = 0;
    while (line_start < len) {
        /* Find end of line */
        line_end = line_start;
        while (line_end < len && data[line_end] != '\n' && data[line_end] != '\r') {
            line_end++;
        }
        
        if (line_end > line_start) {
            line = (gchar*)g_malloc(line_end - line_start + 1);
            tvb_get_nstringz0(tvb, offset + line_start, line_end - line_start, line);
            
            colon = strchr(line, ':');
            if (colon && colon > line) {
                *colon = '\0';
                colon++;
                
                /* Skip leading space after colon */
                while (*colon == ' ') colon++;
                
                if (g_ascii_strcasecmp(line, "event") == 0) {
                    proto_tree_add_string(sse_tree, hf_mcp_sse_event, tvb, 
                                        offset + line_start, strlen(colon), colon);
                } else if (g_ascii_strcasecmp(line, "data") == 0) {
                    proto_tree_add_string(sse_tree, hf_mcp_sse_data, tvb, 
                                        offset + line_start, strlen(colon), colon);
                } else if (g_ascii_strcasecmp(line, "id") == 0) {
                    proto_tree_add_string(sse_tree, hf_mcp_sse_id, tvb, 
                                        offset + line_start, strlen(colon), colon);
                } else if (g_ascii_strcasecmp(line, "retry") == 0) {
                    proto_tree_add_string(sse_tree, hf_mcp_sse_retry, tvb, 
                                        offset + line_start, strlen(colon), colon);
                }
            }
            
            g_free(line);
        }
        
        line_start = line_end + 1;
        if (line_start < len && data[line_end] == '\r' && data[line_start] == '\n') {
            line_start++;
        }
    }
}

/*
 * Dissect params section
 */
static void dissect_mcp_params(tvbuff_t *tvb, proto_tree *tree, int offset, int len)
{
    proto_item *ti_params;
    proto_tree *params_tree;
    const guchar *data;
    gchar *params_str = NULL;
    
    data = tvb_get_ptr(tvb, offset, len);
    if (!data || !g_strstr_len((const gchar*)data, len, "\"params\"")) {
        return;
    }
    
    ti_params = proto_tree_add_item(tree, hf_mcp_params, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
    params_tree = proto_item_add_subtree(ti_params, ett_mcp_params);
    
    /* Look for tool-specific params */
    if (g_strstr_len((const gchar*)data, len, "\"name\"")) {
        gchar *name = NULL;
        if (find_json_string(tvb, offset, len, "\"name\"", &name) > 0 && name) {
            proto_tree_add_string(params_tree, hf_mcp_tool_name, tvb, offset, 
                                strlen(name), name);
            g_free(name);
        }
    }
    
    if (g_strstr_len((const gchar*)data, len, "\"input\"")) {
        proto_tree_add_string(params_tree, hf_mcp_tool_input, tvb, offset, len, "(see JSON)");
    }
    
    if (g_strstr_len((const gchar*)data, len, "\"uri\"")) {
        gchar *uri = NULL;
        if (find_json_string(tvb, offset, len, "\"uri\"", &uri) > 0 && uri) {
            proto_tree_add_string(params_tree, hf_mcp_resource_uri, tvb, offset, 
                                strlen(uri), uri);
            g_free(uri);
        }
    }
}

/*
 * Dissect result section
 */
static void dissect_mcp_result(tvbuff_t *tvb, proto_tree *tree, int offset, int len)
{
    proto_item *ti_result;
    proto_tree *result_tree;
    const guchar *data;
    
    data = tvb_get_ptr(tvb, offset, len);
    if (!data || !g_strstr_len((const gchar*)data, len, "\"result\"")) {
        return;
    }
    
    ti_result = proto_tree_add_item(tree, hf_mcp_result, tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
    result_tree = proto_item_add_subtree(ti_result, ett_mcp_result);
    
    /* Look for tools array */
    if (g_strstr_len((const gchar*)data, len, "\"tools\"")) {
        proto_tree *tools_tree;
        proto_item *ti_tools = proto_tree_add_item(result_tree, hf_mcp_tool_name, 
                                                   tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
        tools_tree = proto_item_add_subtree(ti_tools, ett_mcp_tools);
    }
    
    /* Look for resources array */
    if (g_strstr_len((const gchar*)data, len, "\"resources\"")) {
        proto_tree *res_tree;
        proto_item *ti_res = proto_tree_add_item(result_tree, hf_mcp_resource_uri, 
                                                  tvb, offset, len, ENC_UTF_8|ENC_BIG_ENDIAN);
        res_tree = proto_item_add_subtree(ti_res, ett_mcp_resources);
    }
}

/*
 * Heuristic dissector for detecting MCP in HTTP
 */
static gboolean dissect_mcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const guchar *data_ptr;
    int len;
    
    len = tvb_captured_length(tvb);
    if (len == 0) return FALSE;
    
    data_ptr = tvb_get_ptr(tvb, 0, len);
    if (!data_ptr) return FALSE;
    
    if (is_mcp_content(data_ptr, len)) {
        dissect_mcp(tvb, pinfo, tree, data);
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Register the protocol
 */
void proto_register_mcp(void)
{
    /* Setup protocol structure */
    proto_mcp = proto_register_protocol(
        MCP_NAME,
        "MCP",
        "mcp"
    );
    
    /* Register preferences */
    module_t *mcp_module = prefs_register_protocol(proto_mcp, NULL);
    
    prefs_register_uint_preference(mcp_module, "tcp.port", 
        "MCP TCP Port",
        "Set the TCP port for MCP traffic",
        10, &mcp_tcp_port);
    
    /* Setup header fields */
    static hf_register_info hf[] = {
        { &hf_mcp_type,
            { "Message Type", "mcp.type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP message type", HFILL }
        },
        { &hf_mcp_method,
            { "Method", "mcp.method",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP method name", HFILL }
        },
        { &hf_mcp_jsonrpc_version,
            { "JSON-RPC Version", "mcp.jsonrpc",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "JSON-RPC protocol version", HFILL }
        },
        { &hf_mcp_id,
            { "Message ID", "mcp.id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "JSON-RPC message ID", HFILL }
        },
        { &hf_mcp_id_num,
            { "Message ID (numeric)", "mcp.id.num",
            FT_INT64, BASE_DEC, NULL, 0x0,
            "JSON-RPC message ID (numeric)", HFILL }
        },
        { &hf_mcp_params,
            { "Parameters", "mcp.params",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP method parameters", HFILL }
        },
        { &hf_mcp_result,
            { "Result", "mcp.result",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP method result", HFILL }
        },
        { &hf_mcp_error,
            { "Error", "mcp.error",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "JSON-RPC error", HFILL }
        },
        { &hf_mcp_error_code,
            { "Error Code", "mcp.error.code",
            FT_INT32, BASE_DEC, VALS(jsonrpc_error_codes), 0x0,
            "JSON-RPC error code", HFILL }
        },
        { &hf_mcp_error_message,
            { "Error Message", "mcp.error.message",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "JSON-RPC error message", HFILL }
        },
        { &hf_mcp_error_data,
            { "Error Data", "mcp.error.data",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "JSON-RPC error data", HFILL }
        },
        { &hf_mcp_sse_event,
            { "SSE Event", "mcp.sse.event",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Server-Sent Events event type", HFILL }
        },
        { &hf_mcp_sse_data,
            { "SSE Data", "mcp.sse.data",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Server-Sent Events data", HFILL }
        },
        { &hf_mcp_sse_id,
            { "SSE ID", "mcp.sse.id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Server-Sent Events ID", HFILL }
        },
        { &hf_mcp_sse_retry,
            { "SSE Retry", "mcp.sse.retry",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Server-Sent Events retry interval", HFILL }
        },
        { &hf_mcp_tool_name,
            { "Tool Name", "mcp.tool.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP tool name", HFILL }
        },
        { &hf_mcp_tool_input,
            { "Tool Input", "mcp.tool.input",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP tool input parameters", HFILL }
        },
        { &hf_mcp_resource_uri,
            { "Resource URI", "mcp.resource.uri",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP resource URI", HFILL }
        },
        { &hf_mcp_resource_content,
            { "Resource Content", "mcp.resource.content",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP resource content", HFILL }
        },
        { &hf_mcp_prompt_name,
            { "Prompt Name", "mcp.prompt.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP prompt name", HFILL }
        },
        { &hf_mcp_prompt_args,
            { "Prompt Arguments", "mcp.prompt.args",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP prompt arguments", HFILL }
        }
    };
    
    proto_register_field_array(proto_mcp, hf, array_length(hf));
    
    /* Register subtrees */
    static gint *ett[] = {
        &ett_mcp,
        &ett_mcp_message,
        &ett_mcp_params,
        &ett_mcp_result,
        &ett_mcp_error,
        &ett_mcp_sse,
        &ett_mcp_tools,
        &ett_mcp_resources,
        &ett_mcp_prompts
    };
    
    proto_register_subtree_array(ett, array_length(ett));
}

/*
 * Hook into the dissector table
 */
void proto_reg_handoff_mcp(void)
{
    static dissector_handle_t mcp_handle;
    static guint saved_mcp_port;
    
    mcp_handle = create_dissector_handle(dissect_mcp, proto_mcp);
    
    /* Register for TCP (raw) */
    dissector_add_uint("tcp.port", mcp_tcp_port, mcp_handle);
    
    /* Register heuristic for HTTP detection */
    heur_dissector_add("http", dissect_mcp_heur, proto_mcp, "mcp_over_http", "mcp_http", HEURISTIC_ENABLE);
    
    saved_mcp_port = mcp_tcp_port;
}

/*
 * Known MCP Methods:
 * 
 * Client -> Server:
 *   initialize        - Initialize MCP connection
 *   tools/list        - List available tools
 *   tools/call       - Call a tool with input
 *   resources/list   - List available resources
 *   resources/read  - Read a resource
 *   resources/subscribe - Subscribe to resource changes
 *   resources/unsubscribe - Unsubscribe from resource
 *   prompt/list      - List available prompts
 *   prompt/get       - Get a prompt by name
 *   roots/list       - List root directories
 *   sampling/createMessage - Request LLM sampling
 *
 * Server -> Client:
 *   initialized      - Acknowledge initialization
 *   (responses for above methods)
 *
 * SSE Events:
 *   tools/list       - Tools list changed
 *   resources/list   - Resources list changed  
 *   resources/update - Resource content changed
 *   message          - Sampling message result
 */
