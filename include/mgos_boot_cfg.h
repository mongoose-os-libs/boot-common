/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "mgos_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MGOS_BOOT_CFG_NUM_SLOTS
#define MGOS_BOOT_CFG_NUM_SLOTS 5
#endif

/*
 * Things to consider when changing the size of the record.
 *  - Backward compatibility.
 *  - Must be multiple of 16 to be AES-compatible (16 byte block size).
 */
#ifndef MGOS_BOOT_CFG_REC_SIZE
#define MGOS_BOOT_CFG_REC_SIZE 256
#endif

#ifndef MGOS_BOOT_CFG_MAX_RECS_PER_DEV
#define MGOS_BOOT_CFG_MAX_RECS_PER_DEV 32
#endif

#define MGOS_BOOT_CFG_MAGIC 0x30464342 /* "BCF0" LE */
//#define MGOS_BOOT_CFG_MAGIC 11

struct mgos_boot_slot_cfg {
  uint32_t flags;
  char app_dev[8];
  uintptr_t app_map_addr; /* For slots that are directly memory mapped,
                             the address of the mapping. */
  char fs_dev[8];
} __attribute__((packed));

#define MGOS_BOOT_SLOT_F_VALID (1 << 0)
#define MGOS_BOOT_SLOT_F_WRITEABLE (1 << 1)

struct mgos_boot_slot_state {
  uint32_t app_len;   /* Length of the app data in the slot */
  uintptr_t app_org;  /* Origin address of the firmware in this slot.
                         If state.app_org == config.map_addr, then the slot is
                         directly bootable. */
  uint32_t app_crc32; /* CRC32 of the app data in the slot */
  uint32_t app_flags; /* Flags used by app in this slot. */
  uint8_t err_count;  /* Indication of "badness". */
} __attribute__((packed));

#define MGOS_BOOT_APP_F_FS_CREATED (1 << 0)

struct mgos_boot_slot {
  struct mgos_boot_slot_cfg cfg;
  struct mgos_boot_slot_state state;
} __attribute__((packed));

struct mgos_boot_swap_state {
  int8_t phase;
  int8_t a, b, t;
} __attribute__((packed));

struct mgos_boot_cfg {
  uint32_t magic;
  uint32_t seq; /* Sequencer. Increasing value = newer. */
  uint32_t version;
  uint8_t num_slots;
  int8_t active_slot;
  int8_t revert_slot;
  uint32_t flags;
  struct mgos_boot_swap_state swap;
  struct mgos_boot_slot slots[MGOS_BOOT_CFG_NUM_SLOTS];
} __attribute__((packed));

#define MGOS_BOOT_F_COMMITTED (1 << 0)
#define MGOS_BOOT_F_FIRST_BOOT_A (1 << 1)
#define MGOS_BOOT_F_FIRST_BOOT_B (1 << 2)
#define MGOS_BOOT_F_MERGE_FS (1 << 3)

struct mgos_boot_cfg_record {
  struct mgos_boot_cfg cfg;
  uint8_t padding[MGOS_BOOT_CFG_REC_SIZE - sizeof(struct mgos_boot_cfg) -
                  sizeof(uint32_t)];
  uint32_t crc32; /* CRC32 of the fields above. */
} __attribute__((packed));

#define MGOS_BOOT_CFG_DEV_0 "bcfg0"
#define MGOS_BOOT_CFG_DEV_1 "bcfg1"

bool mgos_boot_cfg_init(void);

struct mgos_boot_cfg *mgos_boot_cfg_get(void);

void mgos_boot_cfg_set_default_slots(struct mgos_boot_cfg *cfg);

void mgos_boot_cfg_dump(const struct mgos_boot_cfg *cfg);

bool mgos_boot_cfg_write(struct mgos_boot_cfg *cfg, bool dump);

int8_t mgos_boot_cfg_find_slot(const struct mgos_boot_cfg *cfg,
                               uintptr_t app_map_addr, int8_t excl1,
                               int8_t excl2);

void mgos_boot_cfg_deinit(void);

#ifdef __cplusplus
}
#endif

CS_CTASSERT(sizeof(struct mgos_boot_cfg_record) == MGOS_BOOT_CFG_REC_SIZE,
            do_not_change_size_of_boot_config_record);
