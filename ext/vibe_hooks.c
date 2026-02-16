#include "vibe_compat.h"

static int
vibe_json_escape(char *dst, size_t dst_size, const char *src)
{
    size_t di = 0;
    size_t si;

    if (!src)
    {
        if (dst_size > 0)
            dst[0] = '\0';
        return 0;
    }

    for (si = 0; src[si] != '\0' && di + 1 < dst_size; si++)
    {
        char c = src[si];
        switch (c)
        {
            case '"':
            case '\\':
                if (di + 2 >= dst_size) goto done;
                dst[di++] = '\\';
                dst[di++] = c;
                break;
            case '\n':
                if (di + 2 >= dst_size) goto done;
                dst[di++] = '\\';
                dst[di++] = 'n';
                break;
            case '\r':
                if (di + 2 >= dst_size) goto done;
                dst[di++] = '\\';
                dst[di++] = 'r';
                break;
            case '\t':
                if (di + 2 >= dst_size) goto done;
                dst[di++] = '\\';
                dst[di++] = 't';
                break;
            default:
                if ((unsigned char)c < 0x20)
                {
                    if (di + 6 >= dst_size) goto done;
                    di += snprintf(dst + di, dst_size - di, "\\u%04x", (unsigned char)c);
                }
                else
                {
                    dst[di++] = c;
                }
                break;
        }
    }

done:
    if (di < dst_size)
        dst[di] = '\0';
    else if (dst_size > 0)
        dst[dst_size - 1] = '\0';

    return (int)di;
}

static const char *
vibe_node_tag_to_ddl(NodeTag tag)
{
    switch (tag)
    {
        case T_CreateStmt:        return "CREATE TABLE";
        case T_IndexStmt:         return "CREATE INDEX";
        case T_CreateFunctionStmt: return "CREATE FUNCTION";
        case T_ViewStmt:          return "CREATE VIEW";
        case T_CreateSchemaStmt:  return "CREATE SCHEMA";
        case T_CreateSeqStmt:     return "CREATE SEQUENCE";
        case T_CreateTrigStmt:    return "CREATE TRIGGER";
        case T_CreateExtensionStmt: return "CREATE EXTENSION";
        case T_AlterTableStmt:    return "ALTER TABLE";
        case T_RenameStmt:        return "RENAME";
        case T_DropStmt:          return "DROP";
        case T_GrantStmt:         return "GRANT";
        case T_GrantRoleStmt:     return "GRANT ROLE";
        case T_CreateRoleStmt:    return "CREATE ROLE";
        case T_AlterRoleStmt:     return "ALTER ROLE";
        case T_DropRoleStmt:      return "DROP ROLE";
        default:                  return NULL;
    }
}

static const char *
vibe_object_type_str(ObjectType objtype)
{
    switch (objtype)
    {
        case OBJECT_TABLE:      return "TABLE";
        case OBJECT_INDEX:      return "INDEX";
        case OBJECT_SEQUENCE:   return "SEQUENCE";
        case OBJECT_VIEW:       return "VIEW";
        case OBJECT_FUNCTION:   return "FUNCTION";
        case OBJECT_SCHEMA:     return "SCHEMA";
        case OBJECT_TRIGGER:    return "TRIGGER";
        case OBJECT_EXTENSION:  return "EXTENSION";
        case OBJECT_ROLE:       return "ROLE";
        default:                return "UNKNOWN";
    }
}

void
vibe_emit_auth_event(Port *port, int status)
{
    char buf[VIBE_MAX_EVENT_SIZE];
    struct timeval tv;
    struct tm *tm_info;
    char timebuf[64];
    const char *user_name;
    const char *db_name;
    const char *remote_host;
    int remote_port;
    const char *app_name;

    gettimeofday(&tv, NULL);
    tm_info = gmtime(&tv.tv_sec);
    snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             (int)(tv.tv_usec / 1000));

    user_name = port->user_name ? port->user_name : "";
    db_name = port->database_name ? port->database_name : "";
    remote_host = port->remote_host ? port->remote_host : "";
    remote_port = atoi(port->remote_port ? port->remote_port : "0");
    app_name = application_name ? application_name : "";

    int len = snprintf(buf, sizeof(buf),
        "{"
        "\"event_type\":\"%s\","
        "\"event_time\":\"%s\","
        "\"success\":%s,"
        "\"session_user\":\"%s\","
        "\"client_addr\":\"%s\","
        "\"client_port\":%d,"
        "\"database\":\"%s\","
        "\"pid\":%d,"
        "\"application\":\"%s\","
        "\"command_tag\":\"authentication\","
        "\"object_type\":null,"
        "\"object_name\":null,"
        "\"schema_name\":null,"
        "\"query_text\":null,"
        "\"sqlstate\":\"%s\","
        "\"detail\":{\"reason\":\"%s\"}"
        "}",
        status == STATUS_OK ? "AUTH_SUCCESS" : "AUTH_FAIL",
        timebuf,
        status == STATUS_OK ? "true" : "false",
        user_name,
        remote_host,
        remote_port,
        db_name,
        MyProcPid,
        app_name,
        status == STATUS_OK ? "00000" : "28P01",
        status == STATUS_OK ? "authentication successful" : "password authentication failed"
    );

    if (len > 0 && len < (int)sizeof(buf))
        vibe_emit_event(buf, len);
}

void
vibe_emit_utility_event(VIBE_UTILITY_HOOK_ARGS)
{
    vibe_emit_utility_event_with_status(VIBE_UTILITY_HOOK_PASSTHROUGH, true);
}

void
vibe_emit_utility_event_with_status(VIBE_UTILITY_HOOK_ARGS, bool success)
{
    Node *utility_stmt;
    const char *ddl_tag;
    char buf[VIBE_MAX_EVENT_SIZE];
    struct timeval tv;
    struct tm *tm_info;
    char timebuf[64];
    const char *schema_name = NULL;
    const char *object_name = NULL;
    const char *object_type = NULL;

    utility_stmt = VIBE_UTILITY_STMT(pstmt);
    if (!utility_stmt)
        return;

    ddl_tag = vibe_node_tag_to_ddl(nodeTag(utility_stmt));
    if (!ddl_tag)
        return;

    switch (nodeTag(utility_stmt))
    {
        case T_CreateStmt:
        {
            CreateStmt *stmt = (CreateStmt *) utility_stmt;
            if (stmt->relation)
            {
                schema_name = stmt->relation->schemaname;
                object_name = stmt->relation->relname;
            }
            object_type = "TABLE";
            break;
        }
        case T_DropStmt:
        {
            DropStmt *stmt = (DropStmt *) utility_stmt;
            object_type = vibe_object_type_str(stmt->removeType);
            break;
        }
        case T_AlterTableStmt:
        {
            AlterTableStmt *stmt = (AlterTableStmt *) utility_stmt;
            if (stmt->relation)
            {
                schema_name = stmt->relation->schemaname;
                object_name = stmt->relation->relname;
            }
            object_type = "TABLE";
            break;
        }
        case T_GrantStmt:
        {
            GrantStmt *stmt = (GrantStmt *) utility_stmt;
            object_type = vibe_object_type_str(stmt->objtype);
            ddl_tag = stmt->is_grant ? "GRANT" : "REVOKE";
            break;
        }
        case T_CreateRoleStmt:
        {
            CreateRoleStmt *stmt = (CreateRoleStmt *) utility_stmt;
            object_name = stmt->role;
            object_type = "ROLE";
            break;
        }
        case T_DropRoleStmt:
        {
            object_type = "ROLE";
            break;
        }
        default:
            break;
    }

    char escaped_query[VIBE_MAX_EVENT_SIZE / 2];
    vibe_json_escape(escaped_query, sizeof(escaped_query), queryString);

    gettimeofday(&tv, NULL);
    tm_info = gmtime(&tv.tv_sec);
    snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             (int)(tv.tv_usec / 1000));

    int len = snprintf(buf, sizeof(buf),
        "{"
        "\"event_type\":\"DDL\","
        "\"event_time\":\"%s\","
        "\"success\":%s,"
        "\"session_user\":\"%s\","
        "\"client_addr\":\"\","
        "\"client_port\":0,"
        "\"database\":\"%s\","
        "\"pid\":%d,"
        "\"application\":\"%s\","
        "\"command_tag\":\"%s\","
        "\"object_type\":%s%s%s,"
        "\"object_name\":%s%s%s,"
        "\"schema_name\":%s%s%s,"
        "\"query_text\":\"%s\","
        "\"sqlstate\":\"00000\","
        "\"detail\":null"
        "}",
        timebuf,
        success ? "true" : "false",
        GetUserNameFromId(GetUserId(), false),
        get_database_name(MyDatabaseId),
        MyProcPid,
        application_name ? application_name : "",
        ddl_tag,
        object_type ? "\"" : "null", object_type ? object_type : "", object_type ? "\"" : "",
        object_name ? "\"" : "null", object_name ? object_name : "", object_name ? "\"" : "",
        schema_name ? "\"" : "null", schema_name ? schema_name : "", schema_name ? "\"" : "",
        escaped_query
    );

    if (len > 0 && len < (int)sizeof(buf))
        vibe_emit_event(buf, len);
}

void
vibe_emit_executor_event(QueryDesc *queryDesc)
{
    char buf[VIBE_MAX_EVENT_SIZE];
    struct timeval tv;
    struct tm *tm_info;
    char timebuf[64];
    const char *cmd_tag;
    char escaped_query[VIBE_MAX_EVENT_SIZE / 2];

    if (!queryDesc || !queryDesc->sourceText)
        return;

    vibe_json_escape(escaped_query, sizeof(escaped_query), queryDesc->sourceText);

    switch (queryDesc->operation)
    {
        case CMD_SELECT:  cmd_tag = "SELECT"; break;
        case CMD_INSERT:  cmd_tag = "INSERT"; break;
        case CMD_UPDATE:  cmd_tag = "UPDATE"; break;
        case CMD_DELETE:  cmd_tag = "DELETE"; break;
        default:          cmd_tag = "UNKNOWN"; break;
    }

    gettimeofday(&tv, NULL);
    tm_info = gmtime(&tv.tv_sec);
    snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             (int)(tv.tv_usec / 1000));

    int len = snprintf(buf, sizeof(buf),
        "{"
        "\"event_type\":\"DML\","
        "\"event_time\":\"%s\","
        "\"success\":true,"
        "\"session_user\":\"%s\","
        "\"client_addr\":\"\","
        "\"client_port\":0,"
        "\"database\":\"%s\","
        "\"pid\":%d,"
        "\"application\":\"%s\","
        "\"command_tag\":\"%s\","
        "\"object_type\":null,"
        "\"object_name\":null,"
        "\"schema_name\":null,"
        "\"query_text\":\"%s\","
        "\"sqlstate\":\"00000\","
        "\"detail\":{\"superuser\":true}"
        "}",
        timebuf,
        GetUserNameFromId(GetUserId(), false),
        get_database_name(MyDatabaseId),
        MyProcPid,
        application_name ? application_name : "",
        cmd_tag,
        escaped_query
    );

    if (len > 0 && len < (int)sizeof(buf))
        vibe_emit_event(buf, len);
}
