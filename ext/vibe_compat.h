#ifndef VIBE_COMPAT_H
#define VIBE_COMPAT_H

#include "postgres.h"

#if PG_VERSION_NUM < 150000
#error "VibeSQL Audit requires PostgreSQL 15 or later"
#endif

#include "fmgr.h"
#include "utils/guc.h"
#include "tcop/utility.h"
#include "executor/executor.h"
#include "libpq/auth.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/timestamp.h"
#include "utils/builtins.h"
#include "tcop/tcopprot.h"
#include "nodes/nodes.h"
#include "nodes/parsenodes.h"

#include <sys/types.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET vibe_socket_t;
#define VIBE_INVALID_SOCKET INVALID_SOCKET
#define vibe_close_socket closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
typedef int vibe_socket_t;
#define VIBE_INVALID_SOCKET (-1)
#define vibe_close_socket close
#endif

#if PG_VERSION_NUM >= 170000
#define VIBE_UTILITY_HOOK_ARGS PlannedStmt *pstmt, const char *queryString, \
    bool readOnlyTree, ProcessUtilityContext context, \
    ParamListInfo params, QueryEnvironment *queryEnv, \
    DestReceiver *dest, QueryCompletion *qc
#define VIBE_UTILITY_HOOK_PASSTHROUGH pstmt, queryString, readOnlyTree, \
    context, params, queryEnv, dest, qc
#define VIBE_UTILITY_STMT(pstmt) ((Node *) pstmt->utilityStmt)
#elif PG_VERSION_NUM >= 150000
#define VIBE_UTILITY_HOOK_ARGS PlannedStmt *pstmt, const char *queryString, \
    bool readOnlyTree, ProcessUtilityContext context, \
    ParamListInfo params, QueryEnvironment *queryEnv, \
    DestReceiver *dest, QueryCompletion *qc
#define VIBE_UTILITY_HOOK_PASSTHROUGH pstmt, queryString, readOnlyTree, \
    context, params, queryEnv, dest, qc
#define VIBE_UTILITY_STMT(pstmt) ((Node *) pstmt->utilityStmt)
#endif

#define VIBE_MAX_EVENT_SIZE 8192
#define VIBE_UDP_CONSECUTIVE_FAIL_THRESHOLD 10

extern vibe_socket_t vibe_udp_socket;
extern struct sockaddr_in vibe_udp_addr;
extern int vibe_udp_consecutive_failures;

extern bool vibe_audit_enabled;
extern int vibe_audit_udp_port;
extern char *vibe_audit_udp_host;

extern void vibe_emit_event(const char *json, int len);
extern void vibe_emit_auth_event(Port *port, int status);
extern void vibe_emit_utility_event(VIBE_UTILITY_HOOK_ARGS);
extern void vibe_emit_executor_event(QueryDesc *queryDesc);

#endif
