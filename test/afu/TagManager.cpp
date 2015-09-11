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
 * Description: TagManager.cpp
 *
 *  This file defines the TagManager class for the test AFU.
 */

#include "TagManager.h"

#include <stdlib.h>

std::set < uint32_t > TagManager::tags_in_use;
int TagManager::num_credits = 0;
int TagManager::max_credits = 0;

bool TagManager::request_tag(uint32_t * new_tag)
{

	if (max_credits == 0)
		warn_msg
		    ("TagManager: attempting to request tag when maximum available credit is 0. Did you forget to set room?");

	// no more available credits
	if (num_credits == 0)
		return false;

	do {
		// randomly generate number between 0 - MAX_TAG_NUM
		*new_tag = (uint32_t) (rand() % (MAX_TAG_NUM + 1));
	} while (tags_in_use.find(*new_tag) != tags_in_use.end());

	tags_in_use.insert(*new_tag);
	--num_credits;

	return true;
}

void TagManager::release_tag(uint32_t * tag)
{
	release_tag(tag, 1);
}

void TagManager::release_tag(uint32_t * tag, int returned_credits)
{
	if (tags_in_use.find(*tag) == tags_in_use.end())
		error_msg("TagManager: attempt to release tag not in use");

	tags_in_use.erase(*tag);
	num_credits += returned_credits;

	if (num_credits > max_credits)
		error_msg
		    ("TagManager: more credits available than maximum allowed credits");
}

bool TagManager::is_in_use(uint32_t * tag)
{

	if (tags_in_use.find(*tag) == tags_in_use.end())
		return false;

	return true;
}

void TagManager::reset()
{
	tags_in_use.clear();
	num_credits = max_credits;
}

void TagManager::set_max_credits(int mc)
{
	max_credits = mc;
	num_credits = max_credits;
}
