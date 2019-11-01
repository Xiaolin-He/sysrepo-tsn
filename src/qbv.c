/**
 * @file qbv.c
 * @author Xiaolin He
 * @brief Plugin for sysrepo datastore for configuration of TSN-QBV function.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <cjson/cJSON.h>

#include "common.h"

#include "main.h"
#include "qbv.h"

int qbv_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	//int rc = SR_ERR_OK;
	//sr_change_iter_t *it = NULL;
	//sr_change_oper_t oper;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("\n --------------- %s is called\n", __func__);
	goto cleanup;
	printf("\n --------------- xpath is: %s\n", path);
	printf("\n\n ========== CURRENT QBV CONFIG ==================\n\n");
	snprintf(xpath, XPATH_MAX_LEN, "%s/ieee802-dot1q-sched:*//*", IF_XPATH);
	print_config_iter(session, xpath);

cleanup:
	//sr_free_change_iter(it);
	return SR_ERR_OK;
}

