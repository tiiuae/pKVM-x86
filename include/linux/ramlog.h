// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Technology Innovation Institute
 *
 * Simple debug log buffer in RAM.
 */
#include <linux/mm.h>

#define RAMLOGSZ (4 * PAGE_SIZE)

#ifdef CONFIG_DEBUG_KERNEL
extern char __rlog[];
extern int __rp;

#define __ramlog(...)							\
	do {								\
		if ((__rp + 128) >= RAMLOGSZ)				\
			__rp = 0;					\
		__rp += snprintf(&__rlog[__rp], 128, __VA_ARGS__);	\
	} while (0)
static inline char *__rlogp(void) { return &__rlog[__rp]; }
#else
#define __ramlog(...)
static inline char *__rlogp(void) { return NULL; }
#endif

