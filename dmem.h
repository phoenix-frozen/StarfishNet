#ifndef STARFISHNET_DMEM_H
#define STARFISHNET_DMEM_H

#include <malloc.h>

#define ALLOCATE(var) var = malloc(sizeof(*var)); assert(var != NULL)
#define ALLOCATE_ARRAY(var, num) var = malloc((num) * sizeof(*var)); assert(var != NULL)
#define FREE(var) free(var); var = NULL

#endif //STARFISHNET_DMEM_H
