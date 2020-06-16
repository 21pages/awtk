/**
 * File:   mem_allocator_pool.h
 * Author: AWTK Develop Team
 * Brief:  mem_allocator_pool
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

#ifndef TK_MEM_ALLOCATOR_POOL_H
#define TK_MEM_ALLOCATOR_POOL_H

#include "tkc/mem_allocator.h"

BEGIN_C_DECLS

typedef struct _mem_pool_t {
  uint32_t block_size : 8;
  uint32_t block_nr : 16;
  uint32_t bits_size : 8;
  uint32_t used;

  uint32_t* bits;
  uint8_t* start;
} mem_pool_t;

#define TK_SET_BIT(v, n) ((v) |= 1UL << (n))
#define TK_CLEAR_BIT(v, n) ((v) &= ~(1UL << (n)))
#define TK_TOGGLE_BIT(v, n) ((v) ^= (1UL << (n)))
#define TK_TEST_BIT(v, n) (((v) >> (n)) & 1U)

static uint32_t mem_pool_get_bits_size(uint8_t block_nr) {
  return (block_nr / 32 + 2) & 0xfffffff0;
}

static uint32_t mem_pool_get_min_size(uint8_t block_size, uint8_t block_nr) {
  uint32_t bits_size = mem_pool_get_bits_size(block_nr);

  return sizeof(mem_pool_t) + bits_size * sizeof(uint32_t) + block_nr * block_size;
}

static inline mem_pool_t* mem_pool_init(uint8_t* addr, uint32_t size, uint8_t block_size,
                                        uint32_t block_nr) {
  mem_pool_t* pool = (mem_pool_t*)addr;
  uint32_t bits_size = mem_pool_get_bits_size(block_nr);
  uint32_t min_size = mem_pool_get_min_size(block_size, block_nr);
  assert(size >= min_size);

  memset(addr, 0x00, size);
  pool->block_nr = block_nr;
  pool->block_size = block_size;
  pool->bits_size = bits_size;
  pool->bits = (uint32_t*)(addr + sizeof(*pool));
  pool->start = (uint8_t*)(pool->bits + pool->bits_size);

  return pool;
}

static inline int32_t mem_pool_get_free_index(mem_pool_t* pool) {
  uint32_t i = 0;
  uint32_t index = 0;
  uint32_t* bits = pool->bits;
  for(i = 0; i < pool->bits_size; i++) {
    if(index > pool->block_nr) {
      break;
    }

    if(bits[i] != 0xffffffff) {
      uint32_t k = 0;
      uint32_t v = bits[i];
      for(k = 0; k < sizeof(v); k++){
        if(TK_TEST_BIT(v, k) == 0){
          TK_SET_BIT(v, k);
          assert(TK_TEST_BIT(v, k) != 0);
          bits[i] = v;
          return i * sizeof(v) + k;
        }
      }
    }
  }

  return -1;
}

static inline void* mem_pool_get(mem_pool_t* pool) {
  int32_t index = mem_pool_get_free_index(pool);

  if(index >= 0) {
    pool->used++;
    return pool->start + index * pool->block_size;
  }

  return NULL;
}

static inline ret_t mem_pool_put_index(mem_pool_t* pool, uint32_t index) {
  uint32_t i = index/sizeof(uint32_t);
  uint32_t k = index%sizeof(uint32_t);
  uint32_t v = pool->bits[i];

  TK_CLEAR_BIT(v, k);
  pool->bits[i] = v;

  return RET_OK;
}

static inline int32_t mem_pool_get_index(mem_pool_t* pool, uint8_t* addr) {
  if(pool->start < addr && addr < (pool->start + pool->block_size * pool->block_nr)) {
    uint32_t offset = addr - pool->start;
    uint32_t index = offset/(pool->block_size);
    assert(offset%pool->block_size == 0);
    return index;
  }

  return -1;
}

static inline ret_t mem_pool_put(mem_pool_t* pool, uint8_t* addr) {
  int32_t index = mem_pool_get_index(pool, addr);
  if(index >= 0) {
    pool->used--;
    return mem_pool_put_index(pool, index);
  }

  return RET_NOT_FOUND;
}

typedef struct _mem_allocator_pool_t {
  mem_allocator_t allocator;
  mem_allocator_t* impl;
  mem_pool_t* pool8;
  mem_pool_t* pool16;
  mem_pool_t* pool32;
} mem_allocator_pool_t;

#define MEM_ALLOCATOR_POOL(allocator) ((mem_allocator_pool_t*)(allocator))

static inline void* mem_allocator_pool_alloc(mem_allocator_t* allocator, uint32_t size,
                                             const char* func, uint32_t line) {
  void* addr = NULL;
  mem_pool_t* pool8 = MEM_ALLOCATOR_POOL(allocator)->pool8;
  mem_pool_t* pool16 = MEM_ALLOCATOR_POOL(allocator)->pool16;
  mem_pool_t* pool32 = MEM_ALLOCATOR_POOL(allocator)->pool32;
  mem_allocator_t* impl = MEM_ALLOCATOR_POOL(allocator)->impl;

  if(size <= 8) {
    addr = mem_pool_get(pool8);
    if(addr != NULL) {
      return addr;
    }
  } else if(size <=16) {
    addr = mem_pool_get(pool16);
    if(addr != NULL) {
      return addr;
    }
  } else if(size <=32) {
    addr = mem_pool_get(pool32);
    if(addr != NULL) {
      return addr;
    }
  }

  addr = mem_allocator_alloc(impl, size, func, line);

  return addr;
}

static inline void* mem_allocator_pool_realloc(mem_allocator_t* allocator, void* ptr, uint32_t size,
                                               const char* func, uint32_t line) {
  void* addr = NULL;
  mem_pool_t* pool8 = MEM_ALLOCATOR_POOL(allocator)->pool8;
  mem_pool_t* pool16 = MEM_ALLOCATOR_POOL(allocator)->pool16;
  mem_pool_t* pool32 = MEM_ALLOCATOR_POOL(allocator)->pool32;
  mem_allocator_t* impl = MEM_ALLOCATOR_POOL(allocator)->impl;

  if(ptr != NULL && mem_pool_get_index(pool8, ptr) >= 0) {
    if(size <= 8) {
      return ptr;
    } else {
      mem_pool_put(pool8, ptr);
      ptr = NULL;
    }
  }
  
  if(ptr != NULL && mem_pool_get_index(pool16, ptr) >= 0) {
    if(size <= 16) {
      return ptr;
    } else {
      mem_pool_put(pool16, ptr);
      ptr = NULL;
    }
  }
  
  if(ptr != NULL && mem_pool_get_index(pool32, ptr) >= 0) {
    if(size <= 32) {
      return ptr;
    } else {
      mem_pool_put(pool32, ptr);
      ptr = NULL;
    }
  }

  addr = mem_allocator_realloc(impl, ptr, size, func, line);

  return addr;
}

static inline void mem_allocator_pool_free(mem_allocator_t* allocator, void* ptr) {
  mem_pool_t* pool8 = MEM_ALLOCATOR_POOL(allocator)->pool8;
  mem_pool_t* pool16 = MEM_ALLOCATOR_POOL(allocator)->pool16;
  mem_pool_t* pool32 = MEM_ALLOCATOR_POOL(allocator)->pool32;
  mem_allocator_t* impl = MEM_ALLOCATOR_POOL(allocator)->impl;

  if(mem_pool_get_index(pool8, ptr) >= 0) {
    mem_pool_put(pool8, ptr);
    return;
  }
  
  if(mem_pool_get_index(pool16, ptr) >= 0) {
    mem_pool_put(pool16, ptr);
    return;
  }
  
  if(mem_pool_get_index(pool32, ptr) >= 0) {
    mem_pool_put(pool32, ptr);
    return;
  }

  mem_allocator_free(impl, ptr);
}

static inline ret_t mem_allocator_pool_dump(mem_allocator_t* allocator) {
  mem_pool_t* pool8 = MEM_ALLOCATOR_POOL(allocator)->pool8;
  mem_pool_t* pool16 = MEM_ALLOCATOR_POOL(allocator)->pool16;
  mem_pool_t* pool32 = MEM_ALLOCATOR_POOL(allocator)->pool32;
  mem_allocator_t* impl = MEM_ALLOCATOR_POOL(allocator)->impl;

  log_debug("pool8: used=%u total=%u\n", pool8->used, pool8->block_nr);
  log_debug("pool16: used=%u total=%u\n", pool16->used, pool16->block_nr);
  log_debug("pool32: used=%u total=%u\n", pool32->used, pool32->block_nr);

  mem_allocator_dump(impl);

  return RET_OK;
}

static inline ret_t mem_allocator_pool_destroy(mem_allocator_t* allocator) {
  mem_pool_t* pool8 = MEM_ALLOCATOR_POOL(allocator)->pool8;
  mem_pool_t* pool16 = MEM_ALLOCATOR_POOL(allocator)->pool16;
  mem_pool_t* pool32 = MEM_ALLOCATOR_POOL(allocator)->pool32;
  mem_allocator_t* impl = MEM_ALLOCATOR_POOL(allocator)->impl;

  mem_allocator_free(impl, pool8);
  mem_allocator_free(impl, pool16);
  mem_allocator_free(impl, pool32);
  mem_allocator_destroy(impl);
  allocator->vt = NULL;

  return RET_OK;
}

static const mem_allocator_vtable_t s_mem_allocator_pool_vtable = {
    .alloc = mem_allocator_pool_alloc,
    .realloc = mem_allocator_pool_realloc,
    .free = mem_allocator_pool_free,
    .dump = mem_allocator_pool_dump,
    .destroy = mem_allocator_pool_destroy};

static inline mem_allocator_t* mem_allocator_pool_create(mem_allocator_t* impl, uint32_t pool8_nr, uint32_t pool16_nr, uint32_t pool32_nr) {
  uint32_t size = 0;
  static mem_allocator_pool_t s_mem_allocator;
  mem_allocator_t* allocator = MEM_ALLOCATOR(&s_mem_allocator);
  return_value_if_fail(impl != NULL, NULL);

  memset(&s_mem_allocator, 0x00, sizeof(&s_mem_allocator));
  allocator->vt = &s_mem_allocator_pool_vtable;

  s_mem_allocator.impl = impl;
  pool8_nr = tk_max(8, pool8_nr);
  pool16_nr = tk_max(16, pool16_nr);
  pool32_nr = tk_max(32, pool32_nr);
  
  size = mem_pool_get_min_size(8, pool8_nr);
  s_mem_allocator.pool8 = mem_allocator_alloc(impl, size, __FUNCTION__, __LINE__);
  ENSURE(s_mem_allocator.pool8 != NULL);
  
  size = mem_pool_get_min_size(16, pool16_nr);
  s_mem_allocator.pool16 = mem_allocator_alloc(impl, size, __FUNCTION__, __LINE__);
  ENSURE(s_mem_allocator.pool16 != NULL);
  
  size = mem_pool_get_min_size(32, pool32_nr);
  s_mem_allocator.pool32 = mem_allocator_alloc(impl, size, __FUNCTION__, __LINE__);
  ENSURE(s_mem_allocator.pool32 != NULL);

  return allocator;
}

END_C_DECLS

#endif /*TK_MEM_ALLOCATOR_POOL_H*/
