#include "vibe_compat.h"

void
vibe_emit_event(const char *json, int len)
{
    ssize_t sent;

    if (vibe_udp_socket == VIBE_INVALID_SOCKET)
        return;

    sent = sendto(vibe_udp_socket, json, len, 0,
                  (struct sockaddr *)&vibe_udp_addr, sizeof(vibe_udp_addr));

    if (sent < 0)
    {
        vibe_udp_consecutive_failures++;

#ifndef _WIN32
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            if (vibe_udp_consecutive_failures >= VIBE_UDP_CONSECUTIVE_FAIL_THRESHOLD)
                elog(LOG, "vibe_audit: UDP send failed %d consecutive times, falling back to elog",
                     vibe_udp_consecutive_failures);
            return;
        }
#endif

        if (vibe_udp_consecutive_failures >= VIBE_UDP_CONSECUTIVE_FAIL_THRESHOLD)
        {
            elog(LOG, "vibe_audit: UDP fallback — %.*s", len, json);
        }
    }
    else
    {
        vibe_udp_consecutive_failures = 0;
    }
}
