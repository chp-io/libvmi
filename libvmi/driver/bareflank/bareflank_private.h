/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * Author: Tamas K Lengyel <lengyelt@ainfosec.com>
 * Author: Christopher Pelloux <git@chp.io>
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef BAREFLANK_PRIVATE_H
#define BAREFLANK_PRIVATE_H

#include <bfhypercall.h>

#define BF_DEBUG(...) dbprint(VMI_DEBUG_BAREFLANK, "--BF: " __VA_ARGS__)
#define BF_ERROR(...) errprint("--BF: " __VA_ARGS__)

#define BF_MAX_VCPU 1

/* GPA remapping helper structs */
typedef struct gpa_flags {
    mv_uint64_t gpa;
    mv_uint64_t flags;
} gpa_flags_t;
typedef struct gpa_remap {
    gpa_flags_t src;
    gpa_flags_t dst;
} gpa_remap_t;

typedef struct bareflank_instance {
    struct mv_handle_t handle;
    char *name;
    uint64_t domainid;
    void *buffer_space;
    GHashTable *remaps;
    bool is_paused;

    // TODO multi vCPU support
    struct bf_events_t {
        bool has_mtf_on;
        bool has_wrcr3_on;
        bool has_mem_access_on;
    } events/*[BF_MAX_VCPU]*/;

    // Map vCPU # to MicroV VPID
    // uint64_t vcpu_to_vpid[BF_MAX_VCPU];

} bareflank_instance_t;

static inline
bareflank_instance_t *bareflank_get_instance(
    vmi_instance_t vmi)
{
    return ((bareflank_instance_t *) vmi->driver.driver_data);
}

status_t
bareflank_init_events(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);

void
bareflank_destroy_events(vmi_instance_t vmi);

#endif /* BAREFLANK_PRIVATE_H */
