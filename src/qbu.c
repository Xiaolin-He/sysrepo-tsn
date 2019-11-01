/**
 * @file qbu.c
 * @author Xiaolin He
 * @brief Plugin for sysrepo datastore for configuration of TSN-QBU function.
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
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "main.h"
#include "qbu.h"

int get_qbu_cfg_data(char *path)
{
}

int parse_qbu(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_val_t *values = NULL;
	sr_val_t *value = NULL;
	size_t count = 0;
	sr_xpath_ctx_t xp_ctx = {0};
	char * ifname = NULL;
	char * tc_str = NULL;
	char tc_str_bak[8] = {0,};
	uint32_t tc_num = 0;
	uint32_t pt_num = 0;
	char * nodename = NULL;
	char temp[NODE_NAME_MAX_LEN] = {0,};
	char ifname_bak[IF_NAME_MAX_LEN] = {0,};

	printf("\n ========== %s is called ==========\n", __func__);

	if (!path || !session)
		return;

	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		printf("Error by sr_get_items: %s", sr_strerror(rc));
		return rc;
	}
	printf("\n get %d items\n", count);
	init_tsn_socket();
	for (size_t i = 0; i < count; i++) {
		ifname = sr_xpath_key_value(values[i].xpath, "interface",
					    "name", &xp_ctx);
		if (strcmp(ifname, ifname_bak)) {
			if (*ifname_bak != '\0') {
				printf("\nstart to config qbu of '%s'\n",
				       ifname_bak);
				printf("pt value is %d", pt_num);
				rc = tsn_qbu_set(ifname_bak, pt_num);
				if (rc < 0) {
					printf("set qbu error, %s!",
						strerror(-rc));
					goto cleanup;
				}
				pt_num = 0;
			}
			snprintf(ifname_bak, IF_NAME_MAX_LEN, ifname);
		}
		sr_xpath_recover(&xp_ctx);
		tc_str = sr_xpath_key_value(values[i].xpath,
					"frame-preemption-status-table",
					"traffic-class", &xp_ctx);
		if (!tc_str)
			continue;

		sr_xpath_recover(&xp_ctx);

		nodename = strrchr(values[i].xpath, '/');
		snprintf(temp, NODE_NAME_MAX_LEN, nodename);
		if (strcmp(nodename, "/traffic-class") == 0) {
			tc_num = values[i].data.uint8_val;
			continue;
		} else if (strcmp(nodename, "/frame-preemption-status")) {
			continue;
		}

		printf("\nnode '%s' of '%d' value is : %s\n",
		       nodename, tc_num, values[i].data.string_val);

		if (strcmp(values[i].data.string_val, "preemptable") == 0)
			pt_num ^=  (1<<tc_num);
	}

	printf("\nstart to config qbu of '%s'\n", ifname_bak);
	printf("pt value is %d", pt_num);
	rc = tsn_qbu_set(ifname_bak, pt_num);
	if (rc < 0) {
		sprintf("set qbu error, %s!", strerror(-rc));
	}
cleanup:
	close_tsn_socket();
	sr_free_values(values, count);

	return errno2sp(-rc);
}
int qbu_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("\n ========== %s is called ==========\n", __func__);
	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", IF_XPATH, QBU_MODULE_NAME);
	rc = parse_qbu(session, xpath);

	return rc;
}

