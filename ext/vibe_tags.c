#include "vibe_compat.h"

/*
 * Phase 3 stub: Sensitive table tagging and per-table audit filtering.
 *
 * This module will provide:
 * - vibe_audit.tag_table(schema, table, sensitivity_level)
 * - vibe_audit.untag_table(schema, table)
 * - ExecutorEnd filtering based on tagged tables instead of superuser-only
 * - PCI DSS cardholder data environment (CDE) table detection
 *
 * For now, the ExecutorEnd hook in vibe_audit.c only fires for superuser
 * sessions. Phase 3 will replace that with tagged-table filtering.
 */
