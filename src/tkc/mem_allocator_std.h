/**
 * File:   mem_allocator_std.h
 * Author: AWTK Develop Team
 * Brief:  mem_allocator_std
 *
 * Copyright (c) 2020 - 2020  Guangzhou ZHIYUAN Electronics Co.,Ltd.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * License file for more details.
 *
 */

/**
 * History:
 * ================================================================
 * 2020-06-16 Li XianJing <xianjimli@hotmail.com> created
 *
 */

#ifndef TK_MEM_ALLOCATOR_STD_H
#define TK_MEM_ALLOCATOR_STD_H

#include "tkc/mem_allocator.h"

BEGIN_C_DECLS

#define MEM_ALLOCATOR_STD(allocator) ((mem_allocator_std_t*)(allocator))

static inline void* mem_allocator_std_alloc(mem_allocator_t* allocator, uint32_t size, const char* func, uint32_t line) {
  return malloc(size);
}

static inline void* mem_allocator_std_calloc(mem_allocator_t* allocator, uint32_t nmemb, uint32_t size, const char* func, uint32_t line) {
  return calloc(nmemb, size);
}

static inline void* mem_allocator_std_realloc(mem_allocator_t* allocator, void* ptr, uint32_t size, const char* func, uint32_t line) {
  return realloc(ptr, size);
}

static inline void mem_allocator_std_free(mem_allocator_t* allocator, void* ptr) {
  free(ptr);
}

static inline ret_t mem_allocator_std_dump(mem_allocator_t* allocator) {
  return RET_OK;
}

static inline ret_t mem_allocator_std_destroy(mem_allocator_t* allocator) {
  allocator->vt = NULL;
  return RET_OK;
}

static const mem_allocator_vtable_t s_mem_allocator_std_vtable = {
  .alloc = mem_allocator_std_alloc,
  .calloc = mem_allocator_std_calloc,
  .realloc = mem_allocator_std_realloc,
  .free = mem_allocator_std_free,
  .dump = mem_allocator_std_dump,
  .destroy = mem_allocator_std_destroy
};

static inline mem_allocator_t* mem_allocator_std_create(void) {
  static mem_allocator_t s_mem_allocator = {
    .vt = &s_mem_allocator_std_vtable
  };
 
  return &s_mem_allocator;
}

END_C_DECLS

#endif /*TK_MEM_ALLOCATOR_STD_H*/

