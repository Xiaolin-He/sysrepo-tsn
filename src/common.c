/**
 * @file common.c
 * @author Xiaolin He
 * @brief common functions for the project.
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
#include <sys/inotify.h>
#include <pthread.h>
#include <errno.h>

#include "common.h"

static pthread_mutex_t tsn_mutex;

void init_tsn_mutex(void)
{
	pthread_mutex_init(&tsn_mutex, NULL);
}

void destroy_tsn_mutex(void)
{
	pthread_mutex_destroy(&tsn_mutex);
}

void init_tsn_socket(void)
{
	pthread_mutex_lock(&tsn_mutex);
	genl_tsn_init();
}

void close_tsn_socket(void)
{
	genl_tsn_close();
	pthread_mutex_unlock(&tsn_mutex);
}

inline uint64_t cal_base_time(struct base_time_s *basetime)
{
	return ((basetime->seconds * 1000000000) + basetime->nanoseconds);
}

inline uint64_t cal_cycle_time(struct cycle_time_s *cycletime)
{
	return ((cycletime->numerator * 1000000000) / cycletime->denominator);
}

int errno2sp(int errtsn)
{
	int errsp = 0;

	switch (errtsn) {
	case SR_ERR_OK:
		break;	
	case EINVAL:
		errsp = SR_ERR_INVAL_ARG;
		break;	
	case ENOMEM:
		errsp = SR_ERR_NOMEM;
		break;
	default:
		errsp = SR_ERR_INVAL_ARG;
	}

	return errsp;
}
void print_change(sr_change_oper_t oper, sr_val_t *val_old,
		sr_val_t *val_new)
{
	switch (oper) {
	case SR_OP_CREATED:
		if (val_new) {
			printf("created new value: ");
			sr_print_val(val_new);
		}
		break;
	case SR_OP_DELETED:
		if (val_old) {
			printf("deleted old value: ");
			sr_print_val(val_old);
		}
		break;
	case SR_OP_MODIFIED:
		if (val_old && val_new) {
			printf("modified:\nold value ");
			sr_print_val(val_old);
			printf("new value ");
			sr_print_val(val_new);
		}
		break;
	case SR_OP_MOVED:
		if (val_new) {
			printf("moved: %s after %s", val_new->xpath,
			       val_old ? val_old->xpath : NULL);
		}
		break;
	}
}

void print_config_iter(sr_session_ctx_t *session, const char *path)
{
	sr_val_t *values = NULL;
	size_t count = 0;
	int rc = SR_ERR_OK;

	if (!path || !session)
		return;

	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		printf("Error by sr_get_items: %s", sr_strerror(rc));
		return;
	}
	for (size_t i = 0; i < count; i++)
		sr_print_val(&values[i]);

	sr_free_values(values, count);
}

