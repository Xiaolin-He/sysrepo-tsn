/**
 * @file common.h
 * @author Xiaolin He
 * @brief header file for common.c.
 *
 * Copyright 2019 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __COMMON_H_
#define __COMMON_H_

#define XPATH_MAX_LEN 200

#include <tsn/genl_tsn.h> /* must ensure no stdbool.h was included before */
#include <linux/tsn.h>
#include <sysrepo.h>
#include <sysrepo/values.h>

void print_change(sr_change_oper_t oper, sr_val_t *val_old, sr_val_t *val_new);
void print_config_iter(sr_session_ctx_t *session, const char *path);

#endif
