/**
 * File:   mem.c
 * Author: AWTK Develop Team
 * Brief:  simple memory manager
 *
 * Copyright (c) 2018 - 2020  Guangzhou ZHIYUAN Electronics Co.,Ltd.
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
 * 2018-01-13 Li XianJing <xianjimli@hotmail.com> created
 *
 */

#include "tkc/mem.h"
#include "tkc/time_now.h"
#include "tkc/mem_allocator_oom.h"

#ifdef ENABLE_MEM_LEAK_CHECK
#include "tkc/mem_allocator_debug.h"
#endif/*ENABLE_MEM_LEAK_CHECK*/

static mem_allocator_t* s_allocator = NULL;

#define MAX_BLOCK_SIZE 0xffff0000

#ifdef HAS_STD_MALLOC
#include "tkc/mem_allocator_std.h"

static mem_allocator_t* mem_allocator_get(void) {
  if (s_allocator != NULL) {
    return s_allocator;
  }

  s_allocator = mem_allocator_std_create();
  s_allocator = mem_allocator_oom_create(s_allocator);
#ifdef ENABLE_MEM_LEAK_CHECK
  s_allocator = mem_allocator_debug_create(s_allocator);
#endif/*ENABLE_MEM_LEAK_CHECK*/

  return s_allocator;
}

#else /*non std memory manager*/
#include "tkc/mem_allocator_lock.h"
#include "tkc/mem_allocator_simple.h"

ret_t tk_mem_init(void* buffer, uint32_t size) {
  s_allocator = mem_allocator_simple_create(buffer, size);
  s_allocator = mem_allocator_oom_create(s_allocator);
  s_allocator = mem_allocator_lock_create(s_allocator);
#ifdef ENABLE_MEM_LEAK_CHECK
  s_allocator = mem_allocator_debug_create(s_allocator);
#endif/*ENABLE_MEM_LEAK_CHECK*/

  return s_allocator != NULL ? RET_OK : RET_FAIL;
}

static mem_allocator_t* mem_allocator_get(void) {
  return s_allocator;
}

#ifndef WITH_SDL
/*export std malloc*/
void* calloc(size_t count, size_t size) {
  return tk_calloc(count, size, __FUNCTION__, __LINE__);
}

void free(void* ptr) {
  tk_free(ptr);
}

void* malloc(size_t size) {
  return tk_alloc(size, __FUNCTION__, __LINE__);
}

void* realloc(void* ptr, size_t size) {
  return tk_realloc(ptr, size, __FUNCTION__, __LINE__);
}
#endif /*WITH_SDL*/

#endif /*HAS_STD_MALLOC*/

void* tk_calloc(uint32_t nmemb, uint32_t size, const char* func, uint32_t line) {
  mem_allocator_t* allocator = mem_allocator_get();
  return_value_if_fail(allocator != NULL, NULL);

  return mem_allocator_calloc(allocator, nmemb, size, func, line);
}

void* tk_realloc(void* ptr, uint32_t size, const char* func, uint32_t line) {
  mem_allocator_t* allocator = mem_allocator_get();
  return_value_if_fail(allocator != NULL, NULL);

  return mem_allocator_realloc(allocator, ptr, size, func, line);
}

void* tk_alloc(uint32_t size, const char* func, uint32_t line) {
  mem_allocator_t* allocator = mem_allocator_get();
  return_value_if_fail(allocator != NULL, NULL);

  return mem_allocator_alloc(allocator, size, func, line);
}

void tk_free(void* ptr) {
  mem_allocator_t* allocator = mem_allocator_get();
  return_if_fail(allocator != NULL);

  mem_allocator_free(allocator, ptr, __FUNCTION__, __LINE__);
}

void tk_mem_dump(void) {
  mem_allocator_t* allocator = mem_allocator_get();
  return_if_fail(allocator != NULL);

  mem_allocator_dump(allocator);
}

mem_stat_t tk_mem_stat(void) {
  mem_stat_t st;
  memset(&st, 0x00, sizeof(st));
  log_debug("tk_mem_stat is not supported\n");

  return st;
}
