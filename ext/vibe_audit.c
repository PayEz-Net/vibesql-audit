#include "vibe_compat.h"

PG_MODULE_MAGIC;

bool vibe_audit_enabled = true;
int vibe_audit_udp_port = 5514;
char *vibe_audit_udp_host = NULL;

vibe_socket_t vibe_udp_socket = VIBE_INVALID_SOCKET;
struct sockaddr_in vibe_udp_addr;
int vibe_udp_consecutive_failures = 0;

static ClientAuthentication_hook_type prev_client_auth_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;
static ExecutorEnd_hook_type prev_executor_end_hook = NULL;

static void vibe_client_auth_hook(Port *port, int status);
static void vibe_process_utility_hook(VIBE_UTILITY_HOOK_ARGS);
static void vibe_executor_end_hook(QueryDesc *queryDesc);
static void vibe_init_socket(void);

void
_PG_init(void)
{
    DefineCustomBoolVariable(
        "vibe_audit.enabled",
        "Enable VibeSQL audit logging",
        NULL,
        &vibe_audit_enabled,
        true,
        PGC_SIGHUP,
        0,
        NULL, NULL, NULL
    );

    DefineCustomIntVariable(
        "vibe_audit.udp_port",
        "UDP port for audit event emission",
        NULL,
        &vibe_audit_udp_port,
        5514,
        1024,
        65535,
        PGC_SIGHUP,
        0,
        NULL, NULL, NULL
    );

    DefineCustomStringVariable(
        "vibe_audit.udp_host",
        "UDP host for audit event emission",
        NULL,
        &vibe_audit_udp_host,
        "127.0.0.1",
        PGC_SIGHUP,
        0,
        NULL, NULL, NULL
    );

    MarkGUCPrefixReserved("vibe_audit");

    vibe_init_socket();

    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = vibe_client_auth_hook;

    prev_process_utility_hook = ProcessUtility_hook;
    ProcessUtility_hook = vibe_process_utility_hook;

    prev_executor_end_hook = ExecutorEnd_hook;
    ExecutorEnd_hook = vibe_executor_end_hook;

    elog(LOG, "vibe_audit: extension loaded (udp=%s:%d)", vibe_audit_udp_host, vibe_audit_udp_port);
}

void
_PG_fini(void)
{
    ClientAuthentication_hook = prev_client_auth_hook;
    ProcessUtility_hook = prev_process_utility_hook;
    ExecutorEnd_hook = prev_executor_end_hook;

    if (vibe_udp_socket != VIBE_INVALID_SOCKET)
    {
        vibe_close_socket(vibe_udp_socket);
        vibe_udp_socket = VIBE_INVALID_SOCKET;
    }
}

static void
vibe_init_socket(void)
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    vibe_udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (vibe_udp_socket == VIBE_INVALID_SOCKET)
    {
        elog(WARNING, "vibe_audit: failed to create UDP socket");
        return;
    }

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(vibe_udp_socket, FIONBIO, &mode);
#else
    int flags = fcntl(vibe_udp_socket, F_GETFL, 0);
    fcntl(vibe_udp_socket, F_SETFL, flags | O_NONBLOCK);
#endif

    memset(&vibe_udp_addr, 0, sizeof(vibe_udp_addr));
    vibe_udp_addr.sin_family = AF_INET;
    vibe_udp_addr.sin_port = htons((uint16_t) vibe_audit_udp_port);
    inet_pton(AF_INET, vibe_audit_udp_host, &vibe_udp_addr.sin_addr);
}

static void
vibe_client_auth_hook(Port *port, int status)
{
    if (prev_client_auth_hook)
        prev_client_auth_hook(port, status);

    if (!vibe_audit_enabled)
        return;

    vibe_emit_auth_event(port, status);
}

static void
vibe_process_utility_hook(VIBE_UTILITY_HOOK_ARGS)
{
    if (vibe_audit_enabled)
        vibe_emit_utility_event(VIBE_UTILITY_HOOK_PASSTHROUGH);

    if (prev_process_utility_hook)
        prev_process_utility_hook(VIBE_UTILITY_HOOK_PASSTHROUGH);
    else
        standard_ProcessUtility(VIBE_UTILITY_HOOK_PASSTHROUGH);
}

static void
vibe_executor_end_hook(QueryDesc *queryDesc)
{
    if (vibe_audit_enabled && superuser())
        vibe_emit_executor_event(queryDesc);

    if (prev_executor_end_hook)
        prev_executor_end_hook(queryDesc);
    else
        standard_ExecutorEnd(queryDesc);
}
