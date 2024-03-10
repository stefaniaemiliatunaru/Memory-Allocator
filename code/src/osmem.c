// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define METADATA_SIZE (sizeof(struct block_meta))
#define MMAP_THRESHOLD (128 * 1024)

struct block_meta *L;

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	size_t ALIGNED_size = ALIGN(size);

	if (ALIGNED_size + METADATA_SIZE < MMAP_THRESHOLD) {
		if (L == NULL) {
			void *L_ptr = sbrk(MMAP_THRESHOLD);

			L = (struct block_meta *) L_ptr;
			L->status = 0;
			L->size = MMAP_THRESHOLD - METADATA_SIZE;
			L->prev = NULL;
			L->next = NULL;
		} else if (L->status == 2) {
			void *L_ptr = sbrk(MMAP_THRESHOLD);

			L->prev = (struct block_meta *) L_ptr;
			L->prev->status = 0;
			L->prev->size = MMAP_THRESHOLD - METADATA_SIZE;
			L->prev->prev = NULL;
			L->prev->next = L;
			L = L->prev;
		}
		struct block_meta *best_block = NULL;
		struct block_meta *aux = NULL;

		for (aux = L; aux->next != NULL && aux->next->status != 2; aux = aux->next) {
			if (aux->status == 0 && aux->size >= ALIGNED_size) {
				if (best_block == NULL)
					best_block = aux;
				else if (best_block->size > aux->size)
					best_block = aux;
			}
		}
		if (aux->status == 0 && aux->size >= ALIGNED_size) {
			if (best_block == NULL)
				best_block = aux;
			else if (best_block->size > aux->size)
				best_block = aux;
		}
		if (best_block == NULL) {
			if (aux->status == 0) {
				void *aux_ptr = (void *) aux + METADATA_SIZE + aux->size;

				aux_ptr = sbrk(ALIGNED_size - aux->size);
				aux->status = 1;
				aux->size = ALIGNED_size;
				aux_ptr = (void *) aux;
				return aux_ptr + METADATA_SIZE;
			}
			if (aux->status != 0) {
				void *aux_ptr = sbrk(METADATA_SIZE + ALIGNED_size);

				if (aux->next == NULL) {
					aux->next = (struct block_meta *) aux_ptr;
					aux->next->status = 1;
					aux->next->size = ALIGNED_size;
					aux->next->next = NULL;
					aux->next->prev = aux;
				} else if (aux->next->status == 2) {
					void *next_aux = aux->next;

					aux->next = (struct block_meta *) aux_ptr;
					aux->next->status = 1;
					aux->next->size = ALIGNED_size;
					aux->next->next = (struct block_meta *) next_aux;
					aux->next->prev = aux;
				}
				return aux_ptr + METADATA_SIZE;
			}
		}
		if (best_block != NULL) {
			if (best_block->size - ALIGNED_size >= METADATA_SIZE + 8) {
				void *aux_ptr = (void *) best_block + METADATA_SIZE + ALIGNED_size;
				struct block_meta *new_cell = (struct block_meta *) aux_ptr;

				new_cell->status = 0;
				new_cell->size = best_block->size - ALIGNED_size - METADATA_SIZE;
				best_block->status = 1;
				best_block->size = ALIGNED_size;
				new_cell->next = best_block->next;
				new_cell->prev = best_block;
				if (new_cell->next != NULL)
					new_cell->next->prev = new_cell;
				best_block->next = new_cell;
				aux_ptr = (void *) best_block;
				return aux_ptr + METADATA_SIZE;
			}
			if (best_block->size - ALIGNED_size < METADATA_SIZE + 8) {
				best_block->status = 1;
				void *aux_ptr = (void *) best_block;

				return aux_ptr + METADATA_SIZE;
			}
		}
	} else if (ALIGNED_size + METADATA_SIZE >= MMAP_THRESHOLD) {
		struct block_meta *aux = NULL;

		if (L != NULL) {
			for (aux = L; aux->next != NULL; aux = aux->next)
				continue;
		}
		void *aux_ptr = mmap(NULL, METADATA_SIZE + ALIGNED_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

		if (aux == NULL) {
			L = (struct block_meta *) aux_ptr;
			L->status = 2;
			L->size = ALIGNED_size;
			L->prev = NULL;
			L->next = NULL;
		} else {
			aux->next = (struct block_meta *) aux_ptr;
			aux->next->status = 2;
			aux->next->size = ALIGNED_size;
			aux->next->prev = aux;
			aux->next->next = NULL;
		}
		return aux_ptr + METADATA_SIZE;
	}
	return NULL;
}

void os_free(void *ptr)
{
	if (L == NULL)
		return;
	struct block_meta *aux = L;
	void *aux_ptr = (void *) L;

	while (aux_ptr + METADATA_SIZE != ptr) {
		aux = aux->next;
		aux_ptr = (void *) aux;
		if (aux == NULL)
			return;
	}
	if (aux->status == 1) {
		aux->status = 0;
	} else if (aux->status == 2) {
		if (aux->prev != NULL)
			aux->prev->next = aux->next;
		else if (aux->prev == NULL)
			L = aux->next;
		if (aux->next != NULL)
			aux->next->prev = aux->prev;
		munmap(aux_ptr, aux->size + METADATA_SIZE);
	}
	aux = L;
	while (aux != NULL) {
		if (aux->status == 0 && aux->next && aux->next->status == 0) {
			aux->size = aux->size + METADATA_SIZE + aux->next->size;
			if (aux->next->next != NULL)
				aux->next->next->prev = aux;
			aux->next = aux->next->next;
		} else {
			aux = aux->next;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size * nmemb == 0)
		return NULL;
	size_t ALIGNED_size = ALIGN(size * nmemb);

	if (ALIGNED_size + METADATA_SIZE < (size_t)getpagesize()) {
		if (L == NULL) {
			void *L_ptr = sbrk(MMAP_THRESHOLD);

			L = (struct block_meta *) L_ptr;
			L->status = 0;
			L->size = MMAP_THRESHOLD - METADATA_SIZE;
			L->prev = NULL;
			L->next = NULL;
		} else if (L->status == 2) {
			void *L_ptr = sbrk(MMAP_THRESHOLD);

			L->prev = (struct block_meta *) L_ptr;
			L->prev->status = 0;
			L->prev->size = MMAP_THRESHOLD - METADATA_SIZE;
			L->prev->prev = NULL;
			L->prev->next = L;
			L = L->prev;
		}
		struct block_meta *best_block = NULL;
		struct block_meta *aux = NULL;

		for (aux = L; aux->next != NULL && aux->next->status != 2; aux = aux->next) {
			if (aux->status == 0 && aux->size >= ALIGNED_size) {
				if (best_block == NULL)
					best_block = aux;
				else if (best_block->size > aux->size)
					best_block = aux;
			}
		}
		if (aux->status == 0 && aux->size >= ALIGNED_size) {
			if (best_block == NULL)
				best_block = aux;
			else if (best_block->size > aux->size)
				best_block = aux;
		}
		if (best_block == NULL) {
			if (aux->status == 0) {
				void *aux_ptr = (void *) aux + METADATA_SIZE + aux->size;

				aux_ptr = sbrk(ALIGNED_size - aux->size);
				aux->status = 1;
				aux->size = ALIGNED_size;
				aux_ptr = (void *) aux;
				memset(aux_ptr + METADATA_SIZE, 0, aux->size);
				return aux_ptr + METADATA_SIZE;
			}
			if (aux->status != 0) {
				void *aux_ptr = sbrk(METADATA_SIZE + ALIGNED_size);

				if (aux->next == NULL) {
					aux->next = (struct block_meta *) aux_ptr;
					aux->next->status = 1;
					aux->next->size = ALIGNED_size;
					aux->next->next = NULL;
					aux->next->prev = aux;
				} else if (aux->next->status == 2) {
					void *next_aux = aux->next;

					aux->next = (struct block_meta *) aux_ptr;
					aux->next->status = 1;
					aux->next->size = ALIGNED_size;
					aux->next->next = (struct block_meta *) next_aux;
					aux->next->prev = aux;
				}
				memset(aux_ptr + METADATA_SIZE, 0, aux->next->size);
				return aux_ptr + METADATA_SIZE;
			}
		} else if (best_block != NULL) {
			if (best_block->size - ALIGNED_size >= METADATA_SIZE + 8) {
				void *aux_ptr = (void *) best_block + METADATA_SIZE + ALIGNED_size;
				struct block_meta *new_cell = (struct block_meta *) aux_ptr;

				new_cell->status = 0;
				new_cell->size = best_block->size - ALIGNED_size - METADATA_SIZE;
				best_block->status = 1;
				best_block->size = ALIGNED_size;
				new_cell->next = best_block->next;
				new_cell->prev = best_block;
				if (new_cell->next != NULL)
					new_cell->next->prev = new_cell;
				best_block->next = new_cell;
				aux_ptr = (void *) best_block;
				memset(aux_ptr + METADATA_SIZE, 0, best_block->size);
				return aux_ptr + METADATA_SIZE;
			}
			if (best_block->size - ALIGNED_size < METADATA_SIZE + 8) {
				best_block->status = 1;
				void *aux_ptr = (void *) best_block;

				memset(aux_ptr + METADATA_SIZE, 0, best_block->size);
				return aux_ptr + METADATA_SIZE;
			}
		}
	} else if (ALIGNED_size + METADATA_SIZE >= (size_t)getpagesize()) {
		struct block_meta *aux = NULL;

		if (L != NULL) {
			for (aux = L; aux->next != NULL; aux = aux->next)
				continue;
		}
		void *aux_ptr = mmap(NULL, METADATA_SIZE + ALIGNED_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

		if (aux == NULL) {
			L = (struct block_meta *) aux_ptr;
			L->status = 2;
			L->size = ALIGNED_size;
			L->prev = NULL;
			L->next = NULL;
			memset(aux_ptr + METADATA_SIZE, 0, L->size);
			return aux_ptr + METADATA_SIZE;
		}
		if (aux != NULL) {
			aux->next = (struct block_meta *) aux_ptr;
			aux->next->status = 2;
			aux->next->size = ALIGNED_size;
			aux->next->prev = aux;
			aux->next->next = NULL;
		}
		memset(aux_ptr + METADATA_SIZE, 0, aux->next->size);
		return aux_ptr + METADATA_SIZE;
	}
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (ptr == NULL)
		return os_malloc(size);
	if (L == NULL)
		return NULL;
	struct block_meta *aux = L;
	void *aux_ptr = (void *) L;

	while (aux_ptr + METADATA_SIZE != ptr) {
		aux = aux->next;
		aux_ptr = (void *) aux;
	}
	if (aux->status == 0)
		return NULL;
	if (aux->status != 0) {
		aux_ptr = os_malloc(size);
		memcpy(aux_ptr, ptr, aux->size < size ? aux->size : size);
		os_free(ptr);
		return aux_ptr;
	}
	return NULL;
}
