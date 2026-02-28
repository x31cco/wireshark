/* packet-mcp.c
 * Dissector for Model Context Protocol (MCP)
 * 
 * MCP is a JSON-RPC 2.0 based protocol for AI <-> tool communication
 * Typically runs over HTTP with SSE for streaming
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/json_stream.h>
#include <epan/strutil.h>
#include <wsutil/utf8_entities.h>
#include <epan/proto.h>

#define MCP_NAME "Model Context Protocol (MCP)"
#define MCP_FCN_NAME "mcp"

#define TCP_PORT_MCP 3000  /* Default MCP server port */

static int proto_mcp = -1;

/* HF (Header Field) indices */
static int hf_mcp_type = -1;
static int hf_mcp_method = -1;
static int hf_mcp_method_call = -1;
static int hf_mcp_method_response = -1;
static int hf_mcp_jsonrpc_version = -1;
static int hf_mcp_id = -1;
static int hf_mcp_params = -1;
static int hf_mcp_result = -1;
static int hf_mcp_error = -1;
static int hf_mcp_error_code = -1;
static int hf_mcp_error_message = -1;
static int hf_mcp_sse_event = -1;
static int hf_mcp_sse_data = -1;

/* Tree variables */
static gint ett_mcp = -1;
static gint ett_mcp_header = -1;
static gint ett_mcp_body = -1;
static gint ett_mcp_error = -1;

/* Dissector function */
static int dissect_mcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *ti_body;
    proto_tree *mcp_tree, *body_tree;
    json_parse_err_t json_err;
    int offset = 0;
    
    /* Check if this looks like MCP traffic */
    /* MCP uses JSON-RPC 2.0, so we look for {"jsonrpc": "2.0", ...} */
    
    /* Set up the protocol tree */
    if (proto_mcp == -1)
        return 0;
        
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCP");
    col_clear(pinfo->cinfo, COL_INFO);
    
    ti = proto_tree_add_item(tree, proto_mcp, tvb, 0, -1, ENC_NA);
    mcp_tree = proto_item_add_subtree(ti, ett_mcp);
    
    /* Try to parse as JSON */
    tvbuff_t *json_tvb = tvb_new_subset_remaining(tvb, offset);
    
    /* Add the raw JSON as a expandable item */
    ti_body = proto_tree_add_item(mcp_tree, hf_mcp_params, tvb, offset, -1, ENC_UTF_8|ENC_BIG_ENDIAN);
    body_tree = proto_item_add_subtree(ti_body, ett_mcp_body);
    
    /* Try to extract JSON-RPC fields */
    /* This is a simplified parser - in production you'd want more robust JSON parsing */
    
    /* Look for jsonrpc version */
    if (tvb_find_strsize(json_tvb, 0, '"')) {
        proto_tree_add_string(mcp_tree, hf_mcp_jsonrpc_version, tvb, offset, 7, "2.0");
        col_add_fstr(pinfo->cinfo, COL_INFO, "MCP JSON-RPC 2.0");
    }
    
    /* Look for method field */
    /* This is a placeholder - real implementation would parse JSON properly */
    /* You would use epan's JSON parsing functions for this */
    
    /* Look for SSE (Server-Sent Events) markers */
    /* MCP streaming uses text/event-stream format */
    {
        const guchar *data = tvb_get_ptr(tvb, 0, tvb_captured_length(tvb));
        if (data && strstr((const char*)data, "event:")) {
            col_append_str(pinfo->cinfo, COL_INFO, " [SSE Stream]");
        }
    }
    
    return tvb_captured_length(tvb);
}

/* HTTP dissector hook */
static void dissect_mcp_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Check if this is MCP over HTTP */
    const guchar *data = tvb_get_ptr(tvb, 0, MIN(1024, tvb_captured_length(tvb)));
    
    if (data) {
        /* Look for MCP indicators */
        if (strstr((const char*)data, "jsonrpc") || 
            strstr((const char*)data, "mcp") ||
            strstr((const char*)data, "tools/list") ||
            strstr((const char*)data, "resources/list") ||
            strstr((const char*)data, "prompt/get")) {
            
            dissect_mcp(tvb, pinfo, tree, NULL);
        }
    }
}

/* Register the protocol */
void proto_register_mcp(void)
{
    /* Setup protocol structure */
    proto_mcp = proto_register_protocol(
        MCP_NAME,
        "MCP",
        "mcp"
    );
    
    /* Register preferences */
    prefs_register_uint_preference(proto_mcp, "tcp.port", 
        "MCP TCP Port",
        "Set the TCP port for MCP traffic",
        10, &TCP_PORT_MCP);
    
    /* Setup header fields */
    static hf_register_info hf[] = {
        { &hf_mcp_type,
            { "Message Type", "mcp.type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_mcp_method,
            { "Method", "mcp.method",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP method name", HFILL }
        },
        { &hf_mcp_method_call,
            { "Method Call", "mcp.method.call",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP method being called", HFILL }
        },
        { &hf_mcp_method_response,
            { "Method Response", "mcp.method.response",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MCP method response", HFILL }
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
            FT_INT32, BASE_DEC, NULL, 0x0,
            "JSON-RPC error code", HFILL }
        },
        { &hf_mcp_error_message,
            { "Error Message", "mcp.error.message",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "JSON-RPC error message", HFILL }
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
        }
    };
    
    proto_register_field_array(proto_mcp, hf, array_length(hf));
    
    /* Register subtrees */
    static gint *ett[] = {
        &ett_mcp,
        &ett_mcp_header,
        &ett_mcp_body,
        &ett_mcp_error
    };
    
    proto_register_subtree_array(ett, array_length(ett));
}

/* Hook into the dissector table */
void proto_reg_handoff_mcp(void)
{
    static dissector_handle_t mcp_handle;
    
    mcp_handle = create_dissector_handle(dissect_mcp, proto_mcp);
    
    /* Register for HTTP traffic */
    dissector_add_uint("http.port", TCP_PORT_MCP, mcp_handle);
    
    /* Also try to detect MCP in any HTTP traffic */
    /* You would need to add heuristic detection here */
}

/*
 * MCP Dissector for Wireshark
 * 
 * Compile with:
 *   mkdir -p build/epan/dissectors
 *   gcc -shared -o packet-mcp.dll packet-mcp.c \
 *       -I../include -I../wsutil \
 *       -L../build/epan/dissectors -lepan -lwsutil
 *
 * Or use CMake as per Wireshark development docs
 *
 * Installation:
 *   Copy packet-mcp.dll to ~/.wireshark/plugins/ (Windows)
 *   or ~/.local/lib/wireshark/plugins/ (Linux)
 */

/*
 * Known MCP Methods (for reference):
 * 
 * Client -> Server:
 *   - tools/list       - List available tools
 *   - tools/call       - Call a tool
 *   - resources/list   - List resources
 *   - resources/read  - Read a resource
 *   - resources/subscribe - Subscribe to resource changes
 *   - prompt/list     - List prompts
 *   - prompt/get     - Get a prompt
 *   - roots/list     - List roots
 *   - sampling/createMessage - Request LLM sampling
 *
 * Server -> Client:
 *   - tools/list      - Return tool list
 *   - resources/list  - Return resource list
 *   - prompt/list    - Return prompt list
 *   - etc.
 */
