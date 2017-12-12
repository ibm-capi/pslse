#include "TagManager.h"

#include <stdlib.h>

std::set < uint32_t > TagManager::tags_in_use;
int TagManager::num_credits = 0;
int TagManager::max_credits = 0;

bool TagManager::request_tag (uint32_t * new_tag)
{

    if (max_credits == 0)
        warn_msg
        ("TagManager: attempting to request tag when maximum available credit is 0. Did you forget to set room?");

    // no more available credits
    if (num_credits == 0)
        return false;

    do {
        // randomly generate number between 0 - MAX_TAG_NUM
        *new_tag = (uint32_t) (rand () % (MAX_TAG_NUM + 1));
    } while (tags_in_use.find (*new_tag) != tags_in_use.end ());

    tags_in_use.insert (*new_tag);

//    debug_msg("TagManager::request_tag: insert new_tag = %d", *new_tag);

    --num_credits;

//    for(std::set<uint32_t>::iterator it=tags_in_use.begin(); it != tags_in_use.end(); ++it)
//	debug_msg("TagManager::request_tag: %d", *it);

    return true;
}

void
TagManager::release_tag (uint32_t tag)
{
//    debug_msg ("=====>TagManager::release_tag: %d", tag);
    release_tag (tag, 1);
}

void
TagManager::release_tag (uint32_t tag, int returned_credits)
{
    if (tags_in_use.find (tag) == tags_in_use.end ())
        error_msg ("TagManager: attempt to release tag not in use");

    tags_in_use.erase (tag);
    num_credits += returned_credits;

    if (num_credits > max_credits)
        error_msg
        ("TagManager: more credits available than maximum allowed credits");
}

bool TagManager::is_in_use (uint32_t tag)
{
    for (std::set<uint32_t>::iterator it=tags_in_use.begin(); it != tags_in_use.end(); it++) {
	debug_msg ("TagManager::is_in_use: tags_in_use = %d", *it);
    }
    
//    debug_msg("TagManager::is_in_use: tag = %d ", tag);
    if (tags_in_use.find (tag) == tags_in_use.end ()) {
	debug_msg ("TagManager::is_in_use: tag = %d return false", tag);
        return false;
    }

    return true;
}

void
TagManager::reset ()
{
    tags_in_use.clear ();
    num_credits = max_credits;
}

void
TagManager::set_max_credits (int mc)
{
    max_credits = mc;
    num_credits = max_credits;
}
