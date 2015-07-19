#ifndef STARFISHNET_DMEM_H
#define STARFISHNET_DMEM_H

#include <malloc.h>
#include <assert.h>

#define ALLOCATE_ARRAY_HARD(var, num) do { var = malloc((num) * sizeof(*var)); assert(var != NULL); } while (0)
#define ALLOCATE_HARD(var) ALLOCATE_ARRAY_HARD(var, 1)

#define ALLOCATE_ARRAY_COND(var, num, fail) do { var = malloc((num) * sizeof(*var)); if(var == NULL) { fail; } } while (0)
#define ALLOCATE_COND(var, fail) ALLOCATE_ARRAY_COND(var, 1, fail)

#define ALLOCATE_ARRAY ALLOCATE_ARRAY_HARD
#define ALLOCATE(var) ALLOCATE_ARRAY(var, 1)

#define FREE(var) do { free(var); var = NULL; } while (0)

#endif //STARFISHNET_DMEM_H
