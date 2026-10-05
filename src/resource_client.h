#ifndef RESOURCE_CLIENT_H
#define RESOURCE_CLIENT_H

#include "resource_pkg.h"

bool rc_init_device(ResourceRoots *roots);
bool rc_enroll_and_update(ResourceRoots *roots, const char *server, const char *group,
                          char package_id[RR_ID_SIZE], char reason[RR_MAX_LINE]);
bool rc_status(ResourceRoots *roots, char *out, size_t out_size);
bool rc_collect_garbage(ResourceRoots *roots, long long *removed_bytes, int *removed_files,
                        char reason[RR_MAX_LINE]);
#endif
