/*
 * Copyright 2014,2015 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBCXL_LOAD_STORE_H
#define LIBCXL_LOAD_STORE_H



#if defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__)

static inline void store64(uint64_t src, uint64_t *dst)
{
	__asm__ __volatile__("sync ; std%U0%X0 %1,%0"
			     : "=m"(*dst)
			     : "r"(src));
}

static inline uint64_t load64(uint64_t *src)
{
	uint64_t ret;

	__asm__ __volatile__("ld%U1%X1 %0,%1; sync"
			     : "=r"(ret)
			     : "m"(*src));
	return ret;
}

#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)

static inline void store64(uint64_t src, uint64_t *dst)
{
	uint32_t d32;

	d32 = (src >> 32);
	__asm__ __volatile__("sync ; stw%U0%X0 %1,%0"
			     : "=m"(*dst)
			     : "r"(d32));
	d32 = src;
	__asm__ __volatile__("sync ; stw%U0%X0 %1,%0"
			     : "=m"(*dst)
			     : "r"(d32));
}

static inline uint64_t load64(uint64_t *src)
{
	uint64_t d;
	uint32_t d32;

	__asm__ __volatile__("lwz%U1%X1 %0,%1; sync"
			     : "=r"(d32)
			     : "m"(*src);
	d = d32;
	__asm__ __volatile__("lwz%U1%X1 %0,%1; sync"
			     : "=r"(d32)
			     : "m"(*src);

	return (d << 32) | d32;
}

#else

static inline void store64(uint64_t src, uint64_t *dst)
{
	__sync_synchronize();
	*dst = src;
}

static inline uint64_t load64(uint64_t *src)
{
	uint64_t ret = *src;
	__sync_synchronize();
	return ret;
}

#endif




#if defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)

static inline void store32(uint32_t src, uint32_t *dst)
{
    __asm__ __volatile__("sync ; stw%U0%X0 %1,%0"
                         : "=m"(*dst)
                         : "r"(src));
}

static inline uint32_t load32(uint32_t *src)
{
	uint32_t ret;
	__asm__ __volatile__("lwz%U1%X1 %0,%1; sync"
			     : "=r"(ret)
			     : "m"(*src));
	return ret;
}

#else

static inline void store32(uint32_t src, uint32_t *dst)
{
	__sync_synchronize();
	*dst = src;
}

static inline uint32_t load32(uint32_t *src)
{
	uint32_t ret = *src;
	__sync_synchronize();
	return ret;
}

#endif



#endif
