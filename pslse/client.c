/*
 * Copyright 2014,2015 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Description: client.c
 *
 * This file contains code for handling client disconnect.
 */

#include "client.h"

void client_drop(struct client *client, int cycles, enum client_state state)
{
	client->idle_cycles = cycles;
	client->pending = 0;
	client->state = state;
	client->mem_access = NULL;
}
