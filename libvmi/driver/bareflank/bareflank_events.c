/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.
 *
 * This file is part of LibVMI.
 *
 * Author: Christopher Pelloux (git@chp.io)
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

#include <string.h>

#include "private.h"

#include "bareflank.h"
#include "bareflank_private.h"

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// Notes:
//
// Some these should become available from Bareflank PAL generated headers once
// we (i.e. Intel MicroV User Space) are added as a target of PAL.

#define mv_get_bits(t, m) (t & m)

#define mv_exit_reason_encoding 0x4402
#define mv_exit_qualification_encoding 0x6400
// Primary exiting controls:
#define mv_primary_processor_based_vm_execution_controls_encoding 0x4002
#define mv_exit_reason_basic_exit_reason_control_register_accesses 28
#define mv_cr_access_type_mask 0x30
#define mv_cr_access_from 4
#define mv_cr_access_type_mov_to_cr 0
#define mv_cr_access_type_mov_from_cr 1
#define mv_cr_num_mask 0xF
#define mv_cr3_load_exiting_mask 0x8000
#define mv_cr3_load_exiting_from 15
#define mv_mtf_mask 0x8000000
#define mv_mtf_from 27
// Secondary exiting controls:
#define mv_secondary_processor_based_vm_execution_controls_encoding 0x401E
#define mv_ept_violation_mask 0x0000000000040000
#define mv_ept_violation_from 18

#define mv_vp_exit_op_next_event_event_mv_vp_exit_t_mask 0xFFFF
#define mv_vp_exit_op_next_event_flags_data_present_mask (0x1 << 31)

struct mv_vmcs_t {
    uint64_t field;
    uint64_t value;
    uint64_t mask;
    uint64_t old_value;
};

static inline void
bf_dbg_print_flags(const char *prefix, uint64_t flags, const char *suffix)
{
#ifndef VMI_DEBUG
    (void) prefix;
    (void) flags;
    (void) suffix;
#else
    char str[4] = {'_', '_', '_', '\0'};

    if (flags & MV_GPA_FLAG_READ_ACCESS) str[0] = 'R';
    if (flags & MV_GPA_FLAG_WRITE_ACCESS) str[1] = 'W';
    if (flags & MV_GPA_FLAG_EXECUTE_ACCESS) str[2] = 'X';

    BF_DEBUG("%s%s%s", prefix?:"", str, suffix?:"");
#endif
}

// -----------------------------------------------------------------------------
// EPT Violation Events
// -----------------------------------------------------------------------------

status_t
process_ept_violation(
    vmi_instance_t vmi,
    vmi_event_t *vmi_event,
    uint64_t vpid,
    uint64_t gpa,
    uint64_t rip,
    uint64_t *eoe_flags,
    enum mv_vp_exit_t ept_access)
{
    event_response_t response;

//
    // bareflank_instance_t *bf = bareflank_get_instance(vmi);
    // mv_status_t mv_ret;
    // uint64_t gpa_flags;
//

    if (vmi_event->mem_event.generic) {
        BF_ERROR(
            "process_ept_violation: generic mem events are not yet supported!");
        return VMI_FAILURE;
    }

    vmi_event->vcpu_id = vpid;
    vmi_event->mem_event.gfn = gpa >> vmi->page_shift;
    vmi_event->mem_event.gla = rip;
    vmi_event->reg_event.out_access =
        ept_access == mv_vp_exit_t_ept_read_violation? VMI_MEMACCESS_R :
        ept_access == mv_vp_exit_t_ept_write_violation? VMI_MEMACCESS_W :
        ept_access == mv_vp_exit_t_ept_execute_violation? VMI_MEMACCESS_X :
        VMI_MEMACCESS_INVALID;

    // TODO: mem_event members valid and gptw

    // TODO: add reg snapshot option for Bareflank.
    if (vmi_event->x86_regs) {
        vmi_event->x86_regs->rip = rip;
    }

    // TODO add option to populate x86_regs snapshot

    vmi->event_callback = 1;
    response = vmi_event->callback(vmi, vmi_event);
    vmi->event_callback = 0;

    // TODO handle response
    (void) response;

    // FIXME
    // *flags |= MV_VP_EXIT_OP_END_OF_EXIT_FLAGS_ADVANCE;
    (void) eoe_flags;

//
    // mv_ret = mv_vm_state_op_gpa_flags(
    //     &bf->handle, bf->domainid, gpa, &gpa_flags);
    // if (mv_ret != MV_STATUS_SUCCESS) {
    //     BF_ERROR("set_mem_access: gpa_flags failed with 0x%lX\n", mv_ret);
    //     return VMI_FAILURE;
    // }
    // gpa_flags |= (MV_GPA_FLAG_READ_ACCESS |
    //               MV_GPA_FLAG_WRITE_ACCESS |
    //               MV_GPA_FLAG_EXECUTE_ACCESS);
    // mv_ret = mv_vm_state_op_set_gpa_flags(
    //     &bf->handle, bf->domainid, gpa, gpa_flags);
    // if (mv_ret != MV_STATUS_SUCCESS) {
    //     BF_ERROR("set_mem_access: gpa_flags failed with 0x%lX\n", mv_ret);
    //     return VMI_FAILURE;
    // }
//

    return VMI_SUCCESS;
}

status_t
mv_turn_ept_violation_exiting(
    vmi_instance_t vmi,
    bool on)
{
    mv_status_t mv_ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    struct mv_vmcs_t vmcs = {
        .field = mv_secondary_processor_based_vm_execution_controls_encoding,
        .mask = mv_ept_violation_mask,
        .value = (on? 1 : 0) << mv_ept_violation_from
    };

    if (bf->events.has_mem_access_on && on) {
        BF_DEBUG("ept_violation: ignoring, already on\n");
        return VMI_SUCCESS;
    }

    if (!bf->events.has_mem_access_on && !on) {
        BF_DEBUG("ept_violation: ignoring, already off\n");
        return VMI_SUCCESS;
    }

    // FIXME: remove MV_VPID_PARENT
    mv_ret = mv_vp_exit_op_vmwrite(
        &bf->handle, MV_VPID_PARENT, vmcs.field, vmcs.value, vmcs.mask,
        &vmcs.old_value);
    if (mv_ret != MV_STATUS_SUCCESS) {
        BF_ERROR("ept_violation: vmwrite failed with 0x%lX\n", mv_ret);
        return VMI_FAILURE;
    }

    bf->events.has_mem_access_on = false;
    return VMI_SUCCESS;
}

status_t
bareflank_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t UNUSED(vmm_pagetable_id))
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    mv_status_t mv_ret;

    bool ept_ve_on = true;
    uint64_t flags;

    mv_ret = mv_vm_state_op_gpa_flags(&bf->handle, bf->domainid, gpfn, &flags);
    if (mv_ret != MV_STATUS_SUCCESS) {
        BF_ERROR("set_mem_access: gpa_flags failed with 0x%lX\n", mv_ret);
        return VMI_FAILURE;
    }

    // TODO save original flags of GPA

    bf_dbg_print_flags("set_mem_access: original flags were ", flags, " \n");

    switch (page_access_flag) {
        case VMI_MEMACCESS_N:
            flags |= (MV_GPA_FLAG_READ_ACCESS |
                      MV_GPA_FLAG_WRITE_ACCESS |
                      MV_GPA_FLAG_EXECUTE_ACCESS);
            // EPT Violation Off
            ept_ve_on = false;
            break;
        case VMI_MEMACCESS_R:
            flags &= (~MV_GPA_FLAG_READ_ACCESS);
            break;
        case VMI_MEMACCESS_W:
            flags &= (~MV_GPA_FLAG_WRITE_ACCESS);
            break;
        case VMI_MEMACCESS_X:
            flags &= (~MV_GPA_FLAG_EXECUTE_ACCESS);
            break;
        case VMI_MEMACCESS_RW:
            flags &= ~(MV_GPA_FLAG_READ_ACCESS | MV_GPA_FLAG_WRITE_ACCESS);
            break;
        case VMI_MEMACCESS_WX:
            flags &= ~(MV_GPA_FLAG_WRITE_ACCESS | MV_GPA_FLAG_EXECUTE_ACCESS);
            break;
        case VMI_MEMACCESS_RWX:
            flags &= ~(MV_GPA_FLAG_READ_ACCESS |
                       MV_GPA_FLAG_WRITE_ACCESS |
                       MV_GPA_FLAG_EXECUTE_ACCESS);
            break;
        default:
            errprint("set_mem_access: invalid memaccess setting requested\n");
            return VMI_FAILURE;
    }

    if (mv_turn_ept_violation_exiting(vmi, ept_ve_on) != VMI_SUCCESS) {
            return VMI_FAILURE;
    }

    mv_ret = mv_vm_state_op_set_gpa_flags(
        &bf->handle, bf->domainid, gpfn, flags);
    if (mv_ret != MV_STATUS_SUCCESS) {
        BF_ERROR("set_mem_access: gpa_flags failed with 0x%lX\n", mv_ret);
        return VMI_FAILURE;
    }

    bf_dbg_print_flags("set_mem_access: new flags are ", flags, " \n");

    return VMI_SUCCESS;
}

// -----------------------------------------------------------------------------
// Control Register Events
// -----------------------------------------------------------------------------

status_t
process_wrcr3(
    vmi_instance_t vmi,
    vmi_event_t *vmi_event,
    uint64_t vpid,
    uint64_t value,
    uint64_t previous,
    uint64_t *flags)
{
    event_response_t response;

    vmi_event->vcpu_id = vpid;
    vmi_event->reg_event.out_access = VMI_REGACCESS_W;
    vmi_event->reg_event.previous = previous;
    vmi_event->reg_event.value = value;

    // TODO add option to populate x86_regs snapshot

    vmi->event_callback = 1;
    response = vmi_event->callback(vmi, vmi_event);
    vmi->event_callback = 0;

    // TODO handle response
    (void) response;

    *flags |= MV_VP_EXIT_OP_END_OF_EXIT_FLAGS_ADVANCE;
    return VMI_SUCCESS;
}

#ifdef BF_VMREAD_DISPATCH
status_t
process_control_register_access(
    vmi_instance_t vmi,
    uint64_t vpid,
    uint64_t qualification)
{
    bareflank_instance_t *bf;
    mv_status_t ret;

    reg_t reg;
    enum mv_reg_t mv_reg;
    uint8_t access =
        mv_get_bits(qualification, mv_cr_access_type_mask) >> mv_cr_access_from;
    vmi_reg_access_t out_access;
    uint8_t num = mv_get_bits(qualification, mv_cr_num_mask);
    uint64_t value;
    uint64_t previous;

    switch (access) {
        case mv_cr_access_type_mov_to_cr:
            out_access = VMI_REGACCESS_W;
            break;
        case mv_cr_access_type_mov_from_cr:
        default:
            BF_ERROR("unhandled access type: 0x%x\n", access);
            return VMI_FAILURE;
    }

    switch (num) {
        case 3:
            reg = CR3;
            mv_reg = mv_reg_t_cr3;
            // TODO get previous value
            break;
        default:
            BF_ERROR("unhandled CR number: %u\n", num);
            return VMI_FAILURE;
    }

    vmi_event_t *vmi_event = g_hash_table_lookup(vmi->reg_events, &reg);

#ifdef ENABLE_SAFETY_CHECKS
    if ( !vmi_event ) {
        BF_ERROR("Unhandled register event caught: 0x%lX\n", reg);
        return VMI_FAILURE;
    }
#endif

    bf = bareflank_get_instance(vmi);

    ret = mv_vp_state_op_reg_val(&bf->handle, vpid, mv_reg, &value);
    if (ret != MV_STATUS_SUCCESS) {
        BF_ERROR(
            "process_control_register_access: unable to get CR3\n");
        return VMI_FAILURE;
    }

    // TODO: get previous using vmread

    if (reg == CR3 && out_access == VMI_REGACCESS_W) {
        return process_wrcr3(vmi, vmi_event, vpid, value, previous);
    }

    return VMI_FAILURE;
}
#endif

status_t
bareflank_set_reg_access(
    vmi_instance_t vmi,
    reg_event_t* event)
{
    mv_status_t ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    bool *has_control_reg_on = NULL;
    struct mv_vmcs_t vmcs = {
        .field = mv_primary_processor_based_vm_execution_controls_encoding,
    };

    switch (event->reg) {
        case CR3:
            if (event->in_access == VMI_REGACCESS_N) {
                // Disable all
                BF_DEBUG("set_reg_access: disabling all cr3 events\n");
                vmcs.mask |= mv_cr3_load_exiting_mask;
                // vmcs.mask |= mv_cr3_store_exiting_mask; // not yet impl
                bf->events.has_wrcr3_on = true;
                has_control_reg_on = &bf->events.has_wrcr3_on;
                break;
            }
            else if (event->in_access == VMI_REGACCESS_W) {
                BF_DEBUG("set_reg_access: enabling write cr3 event\n");
                vmcs.mask |= mv_cr3_load_exiting_mask;
                vmcs.value |= (1 << mv_cr3_load_exiting_from);
                has_control_reg_on = &bf->events.has_wrcr3_on;
            }
            else if (event->in_access == VMI_REGACCESS_R) {
                BF_ERROR("set_reg_access: cr3 read is not yet implemented\n");
                // has_control_reg_on = &bf->events.has_rdcr3_on;
                return VMI_FAILURE;
            }
            break;
        default:
            BF_ERROR(
                "set_reg_accress: (reg 0x%lX)%s%s is not yet implemented\n",
                event->reg,
                event->in_access & VMI_REGACCESS_R ? " read" : "",
                event->in_access & VMI_REGACCESS_W ? " write": "");
            return VMI_FAILURE;
    }

    // FIXME: remove MV_VPID_PARENT
    ret = mv_vp_exit_op_vmwrite(
        &bf->handle, MV_VPID_PARENT, vmcs.field, vmcs.value, vmcs.mask,
        &vmcs.old_value);
    if (ret != MV_STATUS_SUCCESS) {
        BF_ERROR("set_reg_access: vmwrite failed with 0x%lX\n", ret);
        return VMI_FAILURE;
    }

    // Was it turned on or off?
    *has_control_reg_on = vmcs.value != 0;

    BF_DEBUG("set_reg_access: vmcs previous value for field 0x%lX is 0x%lX\n",
        vmcs.field, vmcs.old_value);
    return VMI_SUCCESS;
}

// -----------------------------------------------------------------------------
// Monitor Trap Flag (Single Step) Events
// -----------------------------------------------------------------------------

status_t
process_monitor_trap(
    vmi_instance_t vmi,
    vmi_event_t *vmi_event,
    uint64_t vpid,
    uint64_t gpa,
    uint64_t rip,
    uint64_t *flags)
{
    event_response_t response;

    vmi_event->vcpu_id = vpid;

    vmi_event->ss_event.gla = rip;
    vmi_event->ss_event.gfn = gpa >> vmi->page_shift;
    vmi_event->ss_event.offset = rip & VMI_BIT_MASK(0,11);;

    vmi->event_callback = 1;
    response = vmi_event->callback(vmi, vmi_event);
    vmi->event_callback = 0;

    // TODO handle response
    (void) response;

    // We don't want to advance the vCPU for MTF
    *flags &= ~MV_VP_EXIT_OP_END_OF_EXIT_FLAGS_ADVANCE;

    BF_DEBUG("process_monitor_trap: done\n");
    return VMI_SUCCESS;
}

status_t
bareflank_start_single_step(
    vmi_instance_t vmi,
    single_step_event_t *event)
{
    mv_status_t mv_ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    uint64_t vpid;

    // Read xen_start_single_step for reasons of this check here
    if (!(event->vcpus && event->enable)) {
        return VMI_SUCCESS;
    }

    struct mv_vmcs_t vmcs = {
        .field = mv_primary_processor_based_vm_execution_controls_encoding,
        .mask = mv_mtf_mask,
        .value = 1 << mv_mtf_from
    };

    // FIXME: remove MV_VPID_PARENT
    // for each event.vcpus ...
    vpid = MV_VPID_PARENT;

    mv_ret = mv_vp_exit_op_vmwrite(
        &bf->handle, vpid, vmcs.field, vmcs.value, vmcs.mask,
        &vmcs.old_value);
    if (mv_ret != MV_STATUS_SUCCESS) {
        BF_ERROR("start_single_step: vmwrite failed with 0x%lX\n", mv_ret);
        return VMI_FAILURE;
    }
    bf->events.has_mtf_on = true;

    BF_DEBUG("vmcs previous value for field 0x%lX is 0x%lX\n",
        vmcs.field, vmcs.old_value);

    return VMI_SUCCESS;
}

status_t
bareflank_stop_single_step(
    vmi_instance_t vmi,
    uint32_t vcpu)
{
    mv_status_t mv_ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    struct mv_vmcs_t vmcs = {
        .field = mv_primary_processor_based_vm_execution_controls_encoding,
        .mask = mv_mtf_mask,
        .value = 0
    };

    // FIXME: remove MV_VPID_PARENT
    (void) vcpu;
    mv_ret = mv_vp_exit_op_vmwrite(
        &bf->handle, MV_VPID_PARENT, vmcs.field, vmcs.value, vmcs.mask,
        &vmcs.old_value);
    if (mv_ret != MV_STATUS_SUCCESS) {
        BF_ERROR("stop_single_step: vmwrite failed with 0x%lX\n", mv_ret);
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
bareflank_shutdown_single_step(vmi_instance_t vmi)
{
    mv_status_t mv_ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);
    uint32_t i;

    struct mv_vmcs_t vmcs = {
        .field = mv_primary_processor_based_vm_execution_controls_encoding,
        .value = 0
    };

    // FIXME: remove MV_VPID_PARENT
    if (vmi->num_vcpus > BF_MAX_VCPU) {
        BF_DEBUG("shutdown_single_step: multi vcpus not yet supported\n");
        return VMI_FAILURE;
    }
    for (i = 0; i < vmi->num_vcpus; i++) {
        if (bf->events.has_mtf_on) {
            BF_DEBUG("shutdown_single_step: has_mtf_on to true\n");
        }

        mv_ret = mv_vp_exit_op_vmread(
            &bf->handle, MV_VPID_PARENT, vmcs.field, &vmcs.value);
        if (mv_ret != MV_STATUS_SUCCESS) {
            BF_ERROR(
                "shutdown_single_step: vmread failed with 0x%lX\n", mv_ret);
            return VMI_FAILURE;
        }

        if ((vmcs.value & mv_mtf_mask) == 0) {
            BF_DEBUG("shutdown_single_step: vmread, MTF was disabled\n");
            continue;
        }

        bareflank_stop_single_step(vmi, i);
    }

    return VMI_FAILURE;
}

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

status_t
dispatch_event(
    vmi_instance_t vmi,
    uint64_t vpid,
    uint64_t event,
    uint64_t data0,
    uint64_t data1,
    uint64_t *flags)
{
    vmi_event_t *vmi_event;
    gconstpointer key;

    switch (event) {
        case mv_vp_exit_t_timeout:
            BF_DEBUG("dispatch_event: timeout event\n");
            return VMI_SUCCESS;
        case mv_vp_exit_t_cr3_load_exiting:
            BF_DEBUG("dispatch_event: wrcr3 event\n");
            key = (gconstpointer) CR3;
            vmi_event = g_hash_table_lookup(vmi->reg_events, &key);
            return process_wrcr3(vmi, vmi_event, vpid, data0, data1, flags);
        case mv_vp_exit_t_ept_read_violation:
        case mv_vp_exit_t_ept_write_violation:
        case mv_vp_exit_t_ept_execute_violation:
            if (!g_hash_table_size(vmi->mem_events_on_gfn)) {
                // FIXME
                BF_ERROR("Bareflank doesn't support generic mem access yet.\n");
                return VMI_FAILURE;
            }
            key = (gconstpointer) data0; // gfn
            vmi_event = g_hash_table_lookup(vmi->mem_events_on_gfn, &key);
            // TODO add generic mem access
            // vmi_event = g_hash_table_lookup(vmi->mem_events_generic, &key);
            return process_ept_violation(
                vmi, vmi_event, vpid, data0, data1, flags, event);
        case mv_vp_exit_t_monitor_trap_flag:
            BF_DEBUG("dispatch_event: MTF event\n");
            key = (gconstpointer) vpid;
            vmi_event = g_hash_table_lookup(vmi->ss_events, &key);
            return process_monitor_trap(
                vmi, vmi_event, vpid, data0, data1, flags);
        default:
            BF_ERROR("dispatch_event: unhandled event 0x%lX\n", event);
            break;
    }

    return VMI_FAILURE;
}

#ifdef BF_VMREAD_DISPATCH
bool
dispatch_event_with_vmread(
    vmi_instance_t vmi,
    uint64_t vpid)
{
    status_t ret;
    uint64_t exit_reason;
    uint64_t qualification;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    ret = mv_vp_exit_op_vmread(
        &bf->handle, vpid, mv_exit_reason_encoding, &exit_reason);
    if (ret != MV_STATUS_SUCCESS) {
        BF_ERROR("vmread failed for field 0x4402 with 0x%x\n", ret);
        return false;
    }

    ret = mv_vp_exit_op_vmread(
        &bf->handle, vpid, mv_exit_qualification_encoding, &qualification);
    if (ret != MV_STATUS_SUCCESS) {
        BF_ERROR("vmread failed for field 0x6400 with 0x%x\n", ret);
        return false;
    }

    switch (exit_reason) {
        case mv_exit_reason_basic_exit_reason_control_register_accesses:
            return process_control_register_access(vmi, vpid, qualification);
            break;
        default:
            BF_ERROR("unhandled exit reason 0x%lX\n", exit_reason);
    }
    return false;
}
#endif

/*
status_t
bareflank_set_intr_access(
    vmi_instance_t vmi,
    interrupt_event_t* event,
    bool enabled)
{
    return VMI_FAILURE;
}

status_t
bareflank_set_desc_access_event(
    vmi_instance_t vmi,
    bool enabled)
{
    return VMI_FAILURE;
}
*/

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

status_t
bareflank_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout)
{
    mv_status_t mv_ret;
    status_t ret;
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    uint64_t flags = (uint64_t) timeout << 32;
    uint64_t vpid = 0;
    uint64_t event = 0;
    uint64_t data0 = 0;
    uint64_t data1 = 0;

    enum mv_vp_exit_t mv_exit;

    flags |= (1ULL << 0); // don't fail on no event, wait instead
    flags |= (1ULL << 1); // use timeout value

    BF_DEBUG("events_listen: called\n");
    // TODO move this to kernel.
    mv_ret = mv_vp_exit_op_next_exit(
        &bf->handle, flags, &vpid, &event, &data0, &data1);
    if (mv_ret != MV_STATUS_SUCCESS) {
        BF_ERROR("next_event failed with: 0x%lX\n", mv_ret);
    }

    mv_exit = event & mv_vp_exit_op_next_event_event_mv_vp_exit_t_mask;
    flags = MV_VP_EXIT_OP_END_OF_EXIT_FLAGS_HANDLED;

#ifdef BF_VMREAD_DISPATCH
    ret = dispatch_event_with_vmread(vmi, vpid, &flags);
#else
    if ((ret = dispatch_event(vmi, vpid, mv_exit, data0, data1, &flags))
        != VMI_SUCCESS) {
        BF_ERROR("events_listen: dipatch_event failed\n");
    }
#endif

    // if (mv_exit != mv_vp_exit_t_monitor_trap_flag) {
    //     flags |= MV_VP_EXIT_OP_END_OF_EXIT_FLAGS_ADVANCE;
    // }

    if (mv_exit != mv_vp_exit_t_timeout) {
        mv_ret = mv_vp_exit_op_end_of_exit(&bf->handle, flags);
        if (mv_ret != MV_STATUS_SUCCESS) {
            BF_ERROR("end_of_exit failed with: 0x%lX\n", mv_ret);
            ret = VMI_FAILURE;
        }
    }

    BF_DEBUG("events_listen: end\n");
    return ret;
}

status_t
bareflank_init_events(
    vmi_instance_t vmi,
    uint32_t UNUSED(init_flags),
    vmi_init_data_t *UNUSED(init_data))
{
    vmi->driver.events_listen_ptr = &bareflank_events_listen;
    vmi->driver.set_reg_access_ptr = &bareflank_set_reg_access;

    // vmi->driver.set_intr_access_ptr = &bareflank_set_intr_access;
    vmi->driver.set_mem_access_ptr = &bareflank_set_mem_access;
    BF_DEBUG("Warning: no support for generic mem access yet.\n");
    vmi->driver.start_single_step_ptr = &bareflank_start_single_step;
    vmi->driver.stop_single_step_ptr = &bareflank_stop_single_step;
    vmi->driver.shutdown_single_step_ptr = &bareflank_shutdown_single_step;

    // vmi->driver.set_guest_requested_ptr = &xen_set_guest_requested_event;
    // vmi->driver.set_cpuid_event_ptr = &xen_set_cpuid_event;
    // vmi->driver.set_debug_event_ptr = &xen_set_debug_event;
    // vmi->driver.set_privcall_event_ptr = &xen_set_privcall_event;

    // vmi->driver.set_desc_access_event_ptr = &bareflank_set_desc_access_event;

    // vmi->driver.set_failed_emulation_event_ptr
        // = &xen_set_failed_emulation_event;

    return VMI_SUCCESS;
}

void
bareflank_destroy_events(
    vmi_instance_t vmi)
{
    bareflank_instance_t *bf = bareflank_get_instance(vmi);

    if (bf->events.has_mtf_on) {
        BF_DEBUG("WARNING: destroy_event, MTF is still on. Recovering...\n");
        bf->events.has_mtf_on = false;
        bareflank_shutdown_single_step(vmi);
    }

    if (bf->events.has_wrcr3_on) {
        BF_DEBUG("WARNING: destroy_event, wrcr3 is still on. Recovering...\n");
        bf->events.has_wrcr3_on = false;
        // TODO
    }

    if (bf->events.has_mem_access_on) {
        BF_DEBUG(
            "WARNING: destroy_event, mem events are still on. Recovering...\n");
        bf->events.has_mem_access_on = false;
        mv_turn_ept_violation_exiting(vmi, false);
    }

}
