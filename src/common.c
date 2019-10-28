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

#include "common.h"

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

