MODULE_big = vibe_audit
OBJS = vibe_audit.o vibe_hooks.o vibe_emit.o vibe_tags.o

EXTENSION = vibe_audit
DATA = vibe_audit--1.0.sql vibe_audit--1.1.sql vibe_audit--1.0--1.1.sql

PG_CPPFLAGS = -I$(libpq_srcdir)
SHLIB_LINK = -L$(libdir)

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
