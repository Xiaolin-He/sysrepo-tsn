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

int tsn_config_qbv(char * ifname, struct tsn_qbv_conf *qbvconf_ptr,
		bool bt_f, struct base_time_s *base,
		bool ct_f, struct cycle_time_s *cycle,
		bool enable)
{
	int rc = SR_ERR_OK;
	uint32_t i = 0;

	printf("\n ========== %s is called ==========\n", __func__);

	printf("\n interface name is: %s", ifname);
	if (bt_f)
		qbvconf_ptr->admin.base_time = cal_base_time(base);
	if (ct_f)
		qbvconf_ptr->admin.cycle_time = cal_cycle_time(cycle);

	if (enable)
		printf("\n gate_enable is true");
	else
		printf("\n gate_enable is false");
	printf("\n control list length is: %u",
		qbvconf_ptr->admin.control_list_length);

	for (i = 0; i < qbvconf_ptr->admin.control_list_length;
			i++) {
		printf("\n gate state of index %u is :%d", i,
			(qbvconf_ptr->admin.control_list + i)->gate_state);
		printf("\n gate time interval of index %u is :%d", i,
			(qbvconf_ptr->admin.control_list + i)->time_interval);
	}

	printf("\n admin gatestate is %llu", qbvconf_ptr->admin.gate_states);
	printf("\n base time is %llu", qbvconf_ptr->admin.base_time);
	printf("\n cycle time is %u", qbvconf_ptr->admin.cycle_time);
	printf("\n cycle time ext is %u", qbvconf_ptr->admin.cycle_time_extension);
	printf("\n max sdu is %u\n", qbvconf_ptr->maxsdu);

	rc = tsn_qos_port_qbv_set(ifname, qbvconf_ptr, enable);
	if (rc < 0) {
		printf("\n set qbv error, %s!", strerror(-rc));
		rc = errno2sp(-rc);
		goto out;
	}
out:
	return rc;
}

void clr_qbv(sr_val_t *value, struct tsn_qbv_conf *qbvconf_ptr,
		bool *bt_f, struct base_time_s *base,
		bool *ct_f, struct cycle_time_s *cycle,
		bool *qbv_en)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char * index = NULL;
	char * nodename = NULL;
	struct tsn_qbv_entry *entry = NULL;
	uint64_t u64_val = 0;

	printf("\n ========== %s is called ==========", __func__);

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	printf("\n node name is :%s", nodename);

	if (!strcmp(nodename, "gate-enabled")) {
		*qbv_en = false;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		qbvconf_ptr->admin.gate_states = 0;
	} else if (!strcmp(nodename, "admin-control-list-length")) {
		qbvconf_ptr->admin.control_list_length = 0;
	} else if (!strcmp(nodename, "gate-states-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		entry = qbvconf_ptr->admin.control_list;
		(entry + u64_val)->gate_state = 0;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		entry = qbvconf_ptr->admin.control_list;
		printf("\n clear the %lu th tv", u64_val); 
		(entry + u64_val)->time_interval = 0;
	} else if (!strcmp(nodename, "numerator")) {
		cycle->numerator = 0;
	} else if (!strcmp(nodename, "denominator")) {
		cycle->denominator = 1;
		*ct_f = true;
	} else if (!strcmp(nodename,
			   "admin-cycle-time-extension")) {
		qbvconf_ptr->admin.cycle_time_extension = 0;
	} else if (!strcmp(nodename, "seconds")) {
		base->seconds = 0;
	} else if (!strcmp(nodename, "fractional-seconds")) {
		base->nanoseconds = 0;
		*bt_f = true;
	} else if (!strcmp(nodename, "config-change")) {
		qbvconf_ptr->config_change = 0;
	} else if (!strcmp(nodename, "queue-max-sdu")) {
		sr_xpath_recover(&xp_ctx);
		if (strcmp("0",
			   sr_xpath_key_value(value->xpath,
					      "max-sdu-table",
					      "traffic-class",
					      &xp_ctx)))
			qbvconf_ptr->maxsdu = 0;
	}

	return;
}

int parse_qbv(sr_val_t *value, struct tsn_qbv_conf *qbvconf_ptr,
		bool *bt_f, struct base_time_s *base,
		bool *ct_f, struct cycle_time_s *cycle,
		bool *qbv_en)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char * index = NULL;
	uint8_t u8_val = 0;
	uint32_t u32_val = 0;
	uint64_t u64_val = 0;
	char * nodename = NULL;
	struct tsn_qbv_entry *entry = NULL;

	//printf("\n ========== %s is called ==========", __func__);

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	//printf("\n node name is :%s", nodename);

	if (!strcmp(nodename, "gate-enabled")) {
		*qbv_en = value->data.bool_val;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		u8_val = value->data.uint8_val;
		qbvconf_ptr->admin.gate_states = u8_val;
	} else if (!strcmp(nodename, "admin-control-list-length")) {
		u32_val = value->data.uint32_val;
		qbvconf_ptr->admin.control_list_length = u32_val;
	} else if (!strcmp(nodename, "gate-states-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		entry = qbvconf_ptr->admin.control_list;
		u8_val = value->data.uint8_val;
		(entry + u64_val)->gate_state = u8_val;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		entry = qbvconf_ptr->admin.control_list;
		u32_val = value->data.uint32_val;
		(entry + u64_val)->time_interval = u32_val;
	} else if (!strcmp(nodename, "numerator")) {
		cycle->numerator = value->data.uint32_val;
	} else if (!strcmp(nodename, "denominator")) {
		cycle->denominator = value->data.uint32_val;
		if (!cycle->denominator) {
			printf("\n denominator is zero!");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		*ct_f = true;
	} else if (!strcmp(nodename,
			  "admin-cycle-time-extension")) {
		u32_val = value->data.uint32_val;
		qbvconf_ptr->admin.cycle_time_extension = u32_val;
	} else if (!strcmp(nodename, "seconds")) {
		base->seconds = value->data.uint64_val;
	} else if (!strcmp(nodename, "fractional-seconds")) {
		base->nanoseconds = value->data.uint64_val;
		if (!base->nanoseconds) {
			printf("\n nanoseconds is zero!");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		*bt_f = true;
	} else if (!strcmp(nodename, "config-change")) {
		qbvconf_ptr->config_change = value->data.bool_val;
	} else if (!strcmp(nodename, "queue-max-sdu")) {
		sr_xpath_recover(&xp_ctx);
		if (strcmp("0",
			   sr_xpath_key_value(value->xpath,
					      "max-sdu-table",
					      "traffic-class",
					      &xp_ctx)))
			qbvconf_ptr->maxsdu = value->data.uint32_val;
	}

out:
	return rc;
}

int config_qbv_per_port(sr_session_ctx_t *session, const char *path, bool abort,
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
	bool qbv_en = false;
	struct tsn_qbv_conf *qbvconf_ptr;
	struct cycle_time_s ct = {0};
	struct base_time_s bt = {0};
	bool ct_f = false, bt_f = false;

	printf("\n ========== %s is called ==========\n", __func__);
	qbvconf_ptr = malloc_qbv_memory();
	if (!qbvconf_ptr)
		return errno2sp(ENOMEM);

	init_qbv_memory(qbvconf_ptr);
	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		printf("Error by sr_get_items: %s", sr_strerror(rc));
		if (rc == SR_ERR_NOT_FOUND)
			rc = SR_ERR_OK;
		return rc;
	}

	//printf("\n get %d items", count);
	init_tsn_socket();
	for (i = 0; i < count; i++)
		parse_qbv(&values[i], qbvconf_ptr, &bt_f, &bt,
			  &ct_f, &ct, &qbv_en);

	/* if it is called by abort event, we should use new value */
	if (abort) {
		//printf("\n abort operation");
		rc = sr_get_changes_iter(session, path, &it);
		if (rc != SR_ERR_OK) {
			printf("\n Get changes iter failed for xpath %s", path);
			goto cleanup;
		}
		while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
						&oper, &old_value,
						&new_value))) {
			print_change(oper, old_value, new_value);

			if (oper == SR_OP_DELETED) {
				if (old_value) {
					clr_qbv(old_value, qbvconf_ptr, &bt_f,
						 &bt, &ct_f, &ct, &qbv_en);
					continue;
				} else { 
					init_qbv_memory(qbvconf_ptr);
				}
			} else {
				value = new_value;
			}

			parse_qbv(value, qbvconf_ptr, &bt_f, &bt,
				  &ct_f, &ct, &qbv_en);
		}
		if (rc == SR_ERR_NOT_FOUND)
			rc = SR_ERR_OK;
	}
	rc = tsn_config_qbv(ifname, qbvconf_ptr, &bt_f, &bt,
			    &ct_f, &ct, &qbv_en);
	if (rc < 0) {
		printf("set qbv error, %s!", strerror(-rc));
		rc = errno2sp(-rc);
		goto cleanup;
	}

cleanup:
	close_tsn_socket();
	free_qbv_memory(qbvconf_ptr);
	sr_free_values(values, count);

	return rc;
}

int qbv_config(sr_session_ctx_t *session, const char *path, bool abort)
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
				 QBV_MODULE_NAME);
			rc = config_qbv_per_port(session, xpath, abort, ifname);
			if (rc != SR_ERR_OK)
				break;
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
cleanup:
	return rc;
}

int qbv_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};
	static bool apply_to_dev = false;

	if (sr_xpath_node_name_eq(path, "ieee802-dot1q-sched:max-sdu-table"))
		return rc;

	printf("\n ==========ssssssssss START OF %s ==========", __func__);
	print_ev_type(event);

	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", IF_XPATH,
		 QBV_MODULE_NAME);
	switch (event){
	case SR_EV_VERIFY:
		//rc = parse_qbv(session, xpath);
		if (rc)
			goto out;
		rc = qbv_config(session, xpath, false);
		apply_to_dev = true;
		break;
	case SR_EV_ENABLED:
		//print_subtree_changes(session, xpath);
		rc = qbv_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		//print_subtree_changes(session, xpath);
		break;
	case SR_EV_ABORT:
		//print_subtree_changes(session, xpath);
		if (!apply_to_dev)
			goto out;
		rc = qbv_config(session, xpath, true);
		apply_to_dev = false;
		break;
	default:
		break;
	}
out:
	printf("\n ==========eeeeeeeeeee END OF %s =========================\n",
		__func__);
	return rc;
}

