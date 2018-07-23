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

#include "mgos_boot_cfg.h"

#include <string.h>

#include "common/cs_crc32.h"

#include "mgos_vfs_dev.h"

#include "mgos_boot_dbg.h"

static struct mgos_vfs_dev *s_bcfg0_dev, *s_bcfg1_dev;

static struct mgos_vfs_dev *s_bcfg_dev;
static struct mgos_boot_cfg *s_bcfg;
static size_t s_bcfg_off;

static void mgos_boot_cfg_find_latest_dev(struct mgos_vfs_dev *dev, bool *found,
                                          struct mgos_boot_cfg *cfg,
                                          struct mgos_vfs_dev **cfg_dev,
                                          size_t *cfg_off) {
  struct mgos_boot_cfg_record cfgr;
  size_t dev_size = mgos_vfs_dev_get_size(dev);
  for (size_t off = 0; off < dev_size; off += sizeof(cfgr)) {
    if (mgos_vfs_dev_read(dev, off, sizeof(cfgr), &cfgr) != 0) break;
    if (cfgr.cfg.magic != MGOS_BOOT_CFG_MAGIC) break;
    uint32_t crc32 = cs_crc32(0, &cfgr, sizeof(cfgr) - sizeof(uint32_t));
    if (crc32 != cfgr.crc32) break;
    if (*found && cfgr.cfg.seq <= cfg->seq) break;
    *cfg_dev = dev;
    *cfg_off = off;
    *cfg = cfgr.cfg;
    *found = true;
  }
}

static bool mgos_boot_cfg_write_dev(const struct mgos_boot_cfg *cfg,
                                    struct mgos_vfs_dev *dev, size_t off,
                                    bool dump) {
  const char *what;
  enum mgos_vfs_dev_err r;
  struct mgos_boot_cfg_record cfgr;
  uint32_t crc1;
  memset(&cfgr, 0xff, sizeof(cfgr));
  memcpy(&cfgr.cfg, cfg, sizeof(cfgr.cfg));
  cfgr.crc32 = crc1 = cs_crc32(0, &cfgr, sizeof(cfgr) - sizeof(uint32_t));
  if (off == 0) mgos_vfs_dev_erase(dev, 0, mgos_vfs_dev_get_size(dev));
  r = mgos_vfs_dev_write(dev, off, sizeof(cfgr), &cfgr);
  if (r != 0) {
    what = "write";
    goto out;
  }
  r = mgos_vfs_dev_read(dev, off, sizeof(cfgr), &cfgr);
  if (r != 0) {
    what = "read";
    goto out;
  }
  uint32_t crc2 = cs_crc32(0, &cfgr, sizeof(cfgr) - sizeof(uint32_t));
  if (crc1 != crc2) {
    what = "verify";
    r = MGOS_VFS_DEV_ERR_CORRUPT;
  }
  s_bcfg_dev = dev;
  s_bcfg_off = off;
  what = "write";
out:
  if (r == 0 && dump) {
    mgos_boot_cfg_dump(cfg);
  } else {
    mgos_boot_dbg_printf(
        "Cfg seq %lu %s %s (%d) @ %s:%lu\r\n", (unsigned long) cfg->seq, what,
        (r == 0 ? "ok" : "failed"), r, dev->name, (unsigned long) off);
  }
  return r == 0;
}

bool mgos_boot_cfg_write(struct mgos_boot_cfg *cfg, bool dump) {
  struct mgos_vfs_dev *dev = s_bcfg_dev;
  size_t off;
  cfg->seq++;
  if (s_bcfg_dev == NULL) {
    dev = s_bcfg0_dev;
    off = 0;
  } else {
    off = s_bcfg_off + MGOS_BOOT_CFG_REC_SIZE;
  }
  if (off + MGOS_BOOT_CFG_REC_SIZE > mgos_vfs_dev_get_size(dev) ||
      off >= MGOS_BOOT_CFG_MAX_RECS_PER_DEV * MGOS_BOOT_CFG_REC_SIZE) {
    /* Time to switch devices. */
    dev =
        (dev == s_bcfg0_dev && s_bcfg1_dev != NULL ? s_bcfg1_dev : s_bcfg0_dev);
    off = 0;
  }
  bool res = mgos_boot_cfg_write_dev(cfg, dev, off, dump);
  if (!res) {
    /* Didn't work? Try switching devices with erase. */
    dev =
        (dev == s_bcfg0_dev && s_bcfg1_dev != NULL ? s_bcfg1_dev : s_bcfg0_dev);
    res = mgos_boot_cfg_write_dev(cfg, dev, 0, dump);
  }
  return res;
}

void mgos_boot_cfg_dump(const struct mgos_boot_cfg *cfg) {
  mgos_boot_dbg_printf("Cfg seq %lu nsl %d a %d r %d f 0x%lx(%c%c%c%c)\r\n",
                       (unsigned long) cfg->seq, cfg->num_slots,
                       cfg->active_slot, cfg->revert_slot,
                       (unsigned long) cfg->flags,
                       (cfg->flags & MGOS_BOOT_F_MERGE_FS ? 'M' : '.'),
                       (cfg->flags & MGOS_BOOT_F_FIRST_BOOT_B ? 'F' : '.'),
                       (cfg->flags & MGOS_BOOT_F_FIRST_BOOT_A ? 'f' : '.'),
                       (cfg->flags & MGOS_BOOT_F_COMMITTED ? 'C' : '.'));
  for (int i = 0; i < cfg->num_slots; i++) {
    const struct mgos_boot_slot_cfg *sc = &cfg->slots[i].cfg;
    const struct mgos_boot_slot_state *ss = &cfg->slots[i].state;
    mgos_boot_dbg_printf(
        "%d: 0x%lx(%c%c) %s ma 0x%lx fs %s; %lu org 0x%lx crc 0x%lx f 0x%lx e "
        "%u\r\n",
        i, (unsigned long) sc->flags,
        (sc->flags & MGOS_BOOT_SLOT_F_WRITEABLE ? 'W' : '.'),
        (sc->flags & MGOS_BOOT_SLOT_F_VALID ? 'V' : '.'), sc->app_dev,
        (unsigned long) sc->app_map_addr, sc->fs_dev,
        (unsigned long) ss->app_len, (unsigned long) ss->app_org,
        (unsigned long) ss->app_crc32, (unsigned long) ss->app_flags,
        ss->err_count);
  }
  if (cfg->swap.phase != 0) {
    const struct mgos_boot_swap_state *sws = &cfg->swap;
    mgos_boot_dbg_printf("S: %d <-> %d t %d ph %d\r\n", sws->a, sws->b, sws->t,
                         sws->phase);
  }
}

struct mgos_boot_cfg *mgos_boot_cfg_get(void) {
  return s_bcfg;
}

static bool mgos_boot_cfg_find_latest(void) {
  bool found = false;
  mgos_boot_cfg_find_latest_dev(s_bcfg0_dev, &found, s_bcfg, &s_bcfg_dev,
                                &s_bcfg_off);
  mgos_boot_cfg_find_latest_dev(s_bcfg1_dev, &found, s_bcfg, &s_bcfg_dev,
                                &s_bcfg_off);
  return found;
}

void mgos_boot_cfg_set_default(struct mgos_boot_cfg *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->magic = MGOS_BOOT_CFG_MAGIC;
  cfg->version = 1;
  cfg->flags = MGOS_BOOT_F_COMMITTED;
  cfg->revert_slot = -1;
  mgos_boot_cfg_set_default_slots(cfg);
}

int8_t mgos_boot_cfg_find_slot(const struct mgos_boot_cfg *cfg,
                               uintptr_t app_map_addr, int8_t excl1,
                               int8_t excl2) {
  int8_t res = -1;
  /* We randomize somewhat by starting at different point. */
  for (uint32_t j = 0; j < cfg->num_slots; j++) {
    int8_t i = (int8_t)((cfg->seq + j) % cfg->num_slots);
    const struct mgos_boot_slot *s = &cfg->slots[i];
    /* Can never return an active slot. */
    if (i == cfg->active_slot) continue;
    /* If user doesn't want a particular slot, skip it. */
    if (i == excl1 || i == excl2) continue;
    /* Must match map address, if specified. */
    if (app_map_addr != 0 && s->cfg.app_map_addr != app_map_addr) continue;
    /* Must be a valid writeable slot. */
    if (!(s->cfg.flags & MGOS_BOOT_SLOT_F_VALID)) continue;
    if (!(s->cfg.flags & MGOS_BOOT_SLOT_F_WRITEABLE)) continue;
    /* We have a candidate. see it it's better than what we have. */
    if (res < 0 || s->state.err_count < cfg->slots[res].state.err_count) {
      res = i;
    }
  }
  return res;
}

bool mgos_boot_cfg_init(void) {
  bool res = false;

  s_bcfg = calloc(1, sizeof(*s_bcfg));
  s_bcfg0_dev = mgos_vfs_dev_open(MGOS_BOOT_CFG_DEV_0);
  s_bcfg1_dev = mgos_vfs_dev_open(MGOS_BOOT_CFG_DEV_1);
  if (s_bcfg0_dev == NULL && s_bcfg1_dev == NULL) {
#ifdef MGOS_BOOT_BUILD
    mgos_boot_dbg_printf("No config devs!\r\n");
#endif
    goto out;
  }
  res = mgos_boot_cfg_find_latest();
  if (res) {
    mgos_boot_dbg_printf("Cfg @ %s:%lu\r\n", s_bcfg_dev->name,
                         (unsigned long) s_bcfg_off);
  } else {
#ifdef MGOS_BOOT_BUILD
    mgos_boot_dbg_printf("Writing default config...\r\n");
    mgos_vfs_dev_erase(s_bcfg0_dev, 0, mgos_vfs_dev_get_size(s_bcfg0_dev));
    mgos_vfs_dev_erase(s_bcfg1_dev, 0, mgos_vfs_dev_get_size(s_bcfg1_dev));
    mgos_boot_cfg_set_default(s_bcfg);
    res = mgos_boot_cfg_write(s_bcfg, false /* dump*/);
    /* Try again after writing */
    if (res) res = mgos_boot_cfg_find_latest();
#endif /* MGOS_BOOT_BUILD */
  }
out:
  if (!res) {
    free(s_bcfg);
    s_bcfg = NULL;
  }
  return res;
}

void mgos_boot_cfg_deinit(void) {
  mgos_vfs_dev_close(s_bcfg0_dev);
  mgos_vfs_dev_close(s_bcfg1_dev);
}

/* NB: Do not put init code here. This is invoked too late in app mode
 * and not at all in boot loader. */
bool mgos_bootloader_init(void) {
  return true;
}
