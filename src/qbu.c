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

void parse_qbu(sr_val_t *val, uint32_t *tc, uint32_t *pt,
		sr_change_oper_t *oper)
{
	char * tc_str = NULL;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename = NULL;

	printf("\n ========== %s is called ==========\n", __func__);

	if (val->type == SR_LIST_T || val->type == SR_CONTAINER_PRESENCE_T)
		return;

	tc_str = sr_xpath_key_value(val->xpath,
				    "frame-preemption-status-table",
				    "traffic-class", &xp_ctx);
	if (!tc_str)
		return;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(val->xpath);
	if (strcmp(nodename, "traffic-class") == 0) {
		*tc = val->data.uint8_val;
	} else if (strcmp(nodename, "frame-preemption-status") == 0) {
		if (oper && *oper == SR_OP_DELETED)
			*pt &= ~(1<<*tc);
		else if (strcmp(val->data.string_val, "preemptable") == 0)
			*pt ^=  (1<<*tc);
	}
}

int config_qbu_per_port(sr_session_ctx_t *session, const char *path, bool abort,
		char *ifname)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it = NULL;
	sr_change_oper_t oper;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	sr_val_t *values = NULL;
	sr_val_t *value = NULL;
	size_t count = 0, i = 0;
	uint32_t tc_num = 0;
	uint32_t pt_num = 0;
	//char xpath[XPATH_MAX_LEN] = {0,};

	printf("\n ========== %s is called ==========\n", __func__);
	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		printf("Error by sr_get_items: %s", sr_strerror(rc));
		if (rc == SR_ERR_NOT_FOUND)
			rc = SR_ERR_OK;
		return rc;
	}

	init_tsn_socket();
	for (i = 0; i < count; i++)
		parse_qbu(&values[i], &tc_num, &pt_num, &oper);

	/* if it is called by abort event, we should use new value */
	if (abort) {
		rc = sr_get_changes_iter(session, path, &it);
		if (rc != SR_ERR_OK) {
			printf("Get changes iter failed for xpath %s", path);
			return rc;
		}
		while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
						&oper, &old_value,
						&new_value))) {
			if (oper == SR_OP_CREATED && new_value)
				value = new_value;
			else
				value = old_value;

			parse_qbu(value, &tc_num, &pt_num, &oper);
		}
		if (rc == SR_ERR_NOT_FOUND)
			rc = SR_ERR_OK;
	}
	printf("\nstart to config qbu of '%s'\n", ifname);
	printf("pt value is %d\n", pt_num);
	rc = tsn_qbu_set(ifname, pt_num);
	if (rc < 0) {
		printf("set qbu error, %s!", strerror(-rc));
		rc = errno2sp(-rc);
		goto cleanup;
	}

cleanup:
	close_tsn_socket();
	sr_free_values(values, count);

	return rc;
}

int qbu_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it = NULL;
	sr_val_t *old_value = NULL;
	sr_val_t *new_value = NULL;
	sr_val_t *value = NULL;
	sr_change_oper_t oper;
	char * ifname = NULL;
	char ifname_bak[IF_NAME_MAX_LEN] = {0,};
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("\n ========== %s is called ==========", __func__);
	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		printf("\nError by sr_get_items: %s", sr_strerror(rc));
		goto cleanup;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		ifname = sr_xpath_key_value(value->xpath, "interface",
					    "name", &xp_ctx);
		//sr_print_val(value);
		if (!ifname)
			continue;

		if (strcmp(ifname, ifname_bak)) {
			snprintf(ifname_bak, IF_NAME_MAX_LEN, ifname);
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']/%s:*//*", IF_XPATH, ifname,
				 QBU_MODULE_NAME);
			rc = config_qbu_per_port(session, xpath, abort, ifname);
			if (rc != SR_ERR_OK)
				break;
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
cleanup:
	return rc;
}

int qbu_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	sr_session_refresh(session);
	printf("\n ==========ssssssssss START OF %s ==========", __func__);
	print_ev_type(event);
	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", IF_XPATH,
		 QBU_MODULE_NAME);
	switch (event){
	case SR_EV_VERIFY:
	case SR_EV_ENABLED:
		//print_subtree_changes(session, xpath);
		rc = qbu_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		//print_subtree_changes(session, xpath);
		rc = qbu_config(session, xpath, true);
		break;
	default:
		break;
	}
	printf("\n ==========eeeeeeeeeee END OF %s ===========================\n",
		__func__);

	return rc;
}

