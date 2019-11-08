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

struct tsn_qbv_conf *malloc_qbv_memory(void)
{
	struct tsn_qbv_conf *qbvconf_ptr;
	struct tsn_qbv_entry *qbv_entry = NULL;

	printf("\n ========== %s is called ==========\n", __func__);
	/* applying memory for qbv configuration data */
	qbvconf_ptr = (struct tsn_qbv_conf *)malloc(sizeof(struct tsn_qbv_conf));
	if (!qbvconf_ptr) {
		return NULL;
	}
	qbv_entry = (struct tsn_qbv_entry *)malloc(MAX_ENTRY_SIZE);
	if (!qbv_entry) {
		free(qbvconf_ptr);
		return NULL;
	}
	qbvconf_ptr->admin.control_list = qbv_entry;
	return qbvconf_ptr;
}

void init_qbv_memory(struct tsn_qbv_conf *qbvconf_ptr)
{
	struct tsn_qbv_entry *qbv_entry = NULL;

	printf("\n ========== %s is called ==========\n", __func__);
	qbv_entry = qbvconf_ptr->admin.control_list;
	memset(qbv_entry, 0, MAX_ENTRY_SIZE);
	memset(qbvconf_ptr, 0, sizeof(struct tsn_qbv_conf));
	qbvconf_ptr->admin.control_list = qbv_entry;
	printf("\n ========== %s is end ==========\n", __func__);
}

void free_qbv_memory(struct tsn_qbv_conf *qbvconf_ptr)
{
	printf("\n ========== %s is called ==========\n", __func__);
	free(qbvconf_ptr->admin.control_list);
	free(qbvconf_ptr);
}

int config_qbv(char * ifname, struct tsn_qbv_conf *qbvconf_ptr,
		bool bt_f, struct base_time_s *base,
		bool ct_f, struct cycle_time_s *cycle,
		bool enable)
{
	int rc = SR_ERR_OK;

	printf("\n ========== %s is called ==========\n", __func__);
	if (*ifname == '\0') {
		printf("\ninterface name is none");
		rc = SR_ERR_INVAL_ARG;
		goto out;
	}
	printf("\nstart to config qbv of '%s'\n", ifname);
	if (bt_f)
		qbvconf_ptr->admin.base_time = cal_base_time(base);
	if (ct_f)
		qbvconf_ptr->admin.cycle_time = cal_cycle_time(cycle);
	rc = tsn_qos_port_qbv_set(ifname, qbvconf_ptr, enable);
	printf("gate st of index 0 is :%d\n", (qbvconf_ptr->admin.control_list)->gate_state);
	printf("gate tv of index 0 is :%d\n", (qbvconf_ptr->admin.control_list)->time_interval);
	printf("gate st of index 1 is :%d\n", (qbvconf_ptr->admin.control_list + 1)->gate_state);
	printf("gate tv of index 1 is :%d\n", (qbvconf_ptr->admin.control_list + 1)->time_interval);
	printf("base time is %ld\n", qbvconf_ptr->admin.base_time);
	printf("cycle time is %ld\n", qbvconf_ptr->admin.cycle_time);
	if (rc < 0) {
		printf("set qbv error, %s!", strerror(-rc));
		rc = SR_ERR_INTERNAL;
		goto out;
	}
out:
	return rc;
}

int parse_qbv(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_val_t *values = NULL;
	size_t count = 0;
	sr_xpath_ctx_t xp_ctx = {0};
	char * ifname = NULL;
	char * index = NULL;
	uint8_t u8_val = 0;
	uint32_t u32_val = 0;
	uint64_t u64_val = 0;
	char * nodename = NULL;
	struct tsn_qbv_conf *qbvconf_ptr;
	struct tsn_qbv_entry *entry;
	bool qbv_en = false;
	char temp[NODE_NAME_MAX_LEN] = {0,};
	char ifname_bak[IF_NAME_MAX_LEN] = {0,};
	struct cycle_time_s ct = {0};
	struct base_time_s bt = {0};
	bool ct_f = false, bt_f = false;

	printf("\n ========== %s is called ==========\n", __func__);

	if (!path || !session)
		return EINVAL;

	qbvconf_ptr = malloc_qbv_memory();
	if (!qbvconf_ptr)
		return ENOMEM;

	init_qbv_memory(qbvconf_ptr);
	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		printf("Error by sr_get_items: %s", sr_strerror(rc));
		return rc;
	}
	printf("\n get %ld items\n", count);
	init_tsn_socket();
	for (size_t i = 0; i < count; i++) {
		ifname = sr_xpath_key_value(values[i].xpath, "interface",
					    "name", &xp_ctx);
		if (*ifname_bak == '\0')
			snprintf(ifname_bak, IF_NAME_MAX_LEN, ifname);
		if (strcmp(ifname, ifname_bak)) {
			if (config_qbv(ifname_bak, qbvconf_ptr, bt_f, &bt,
				       ct_f, &ct, qbv_en) != SR_ERR_OK)
				goto cleanup;
			init_qbv_memory(qbvconf_ptr);
			snprintf(ifname_bak, IF_NAME_MAX_LEN, ifname);
		}

		sr_xpath_recover(&xp_ctx);
		nodename = strrchr(values[i].xpath, '/');
		printf("node name is :%s\n", nodename);
		snprintf(temp, NODE_NAME_MAX_LEN, nodename);
		if (!strcmp(nodename, "/gate-enabled")) {
			qbv_en = values[i].data.bool_val;
			if (qbv_en)
				printf("gate_enable is true\n");
			else
				printf("gate_enable is false\n");
			continue;
		} else if (!strcmp(nodename, "/admin-gate-states")) {
			u8_val = values[i].data.uint8_val;
			qbvconf_ptr->admin.gate_states = u8_val;
			printf("admin gate state is %x\n", u8_val);
			continue;
		} else if (!strcmp(nodename, "/admin-control-list-length")) {
			u32_val = values[i].data.uint32_val;
			qbvconf_ptr->admin.control_list_length = u32_val;
			printf("gate list lenth is %d\n", u32_val);
			continue;
		} else if (!strcmp(nodename, "/gate-states-value")) {
			sr_xpath_recover(&xp_ctx);
			index = sr_xpath_key_value(values[i].xpath,
						   "admin-control-list",
						   "index", &xp_ctx);
			u64_val = strtoul(index, NULL, 0);
			entry = qbvconf_ptr->admin.control_list;
			u8_val = values[i].data.uint8_val;
			(entry + u64_val)->gate_state = u8_val;
			printf("time state of index '%ld' is:%x\n",
				u64_val, u8_val);
			continue;
		} else if (!strcmp(nodename, "/time-interval-value")) {
			sr_xpath_recover(&xp_ctx);
			index = sr_xpath_key_value(values[i].xpath,
						   "admin-control-list",
						   "index", &xp_ctx);
			u64_val = strtoul(index, NULL, 0);
			entry = qbvconf_ptr->admin.control_list;
			u32_val = values[i].data.uint32_val;
			(entry + u64_val)->time_interval = u32_val;
			printf("time interval of index '%ld' is:%d\n",
				u64_val, u32_val);
			continue;
		} else if (!strcmp(nodename, "/numerator")) {
			ct.numerator = values[i].data.uint32_val;
			continue;
		} else if (!strcmp(nodename, "/denominator")) {
			ct.denominator = values[i].data.uint32_val;
			if (!ct.denominator) {
				printf("\ndenominator is zero!\n");
				goto cleanup;
			}
			ct_f = true;
			continue;
		} else if (!strcmp(nodename,
				  "/sched:admin-cycle-time-extension")) {
			u32_val = values[i].data.uint32_val;
			qbvconf_ptr->admin.cycle_time_extension = u32_val;
			continue;
		} else if (!strcmp(nodename, "/seconds")) {
			bt.seconds = values[i].data.uint64_val;
			continue;
		} else if (!strcmp(nodename, "/fractional-seconds")) {
			bt.nanoseconds = values[i].data.uint64_val;
			if (!bt.nanoseconds) {
				printf("\nnanoseconds is zero!\n");
				goto cleanup;
			}
			bt_f = true;
			continue;
		} else if (!strcmp(nodename, "/config-change")) {
			qbvconf_ptr->config_change = values[i].data.bool_val;
			continue;
		} else if (!strcmp(nodename, "/queue-max-sdu")) {
			sr_xpath_recover(&xp_ctx);
			if (strcmp("0",
				   sr_xpath_key_value(values[i].xpath,
						      "max-sdu-table",
						      "traffic-class",
						      &xp_ctx)))
				qbvconf_ptr->maxsdu = values[i].data.uint32_val;
			continue;
		}
	}

	rc = config_qbv(ifname_bak, qbvconf_ptr, bt_f, &bt, ct_f, &ct, qbv_en);
cleanup:
	close_tsn_socket();
	free_qbv_memory(qbvconf_ptr);
	sr_free_values(values, count);

	return errno2sp(-rc);
}

int qbv_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	if (event != SR_EV_VERIFY)
		return rc;
	printf("\n ========== %s is called ==========\n", __func__);
	printf("xpath is: %s\n", path);
	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", IF_XPATH, QBV_MODULE_NAME);
	rc = parse_qbv(session, xpath);

	return rc;
}

