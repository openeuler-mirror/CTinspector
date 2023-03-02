#ifndef _UB_LIST_H_
#define _UB_LIST_H_

#include <unistd.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define OBJ_OFFSETOF(obj_ptr, field) offsetof(typeof(*(obj_ptr)), field)
#define SIZEOF_FIELD(struct_type, field) (sizeof(((struct_type *)NULL)->field))

#ifdef __cplusplus
}
#endif

#endif