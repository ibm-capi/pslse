#ifndef __tag_manager_h__
#define __tag_manager_h__

extern "C" {
#include "utils.h"
}

#include <stdint.h>
#include <set>

#define MAX_TAG_NUM 255

class TagManager
{
private:
    static std::set < uint32_t > tags_in_use;
    static int num_credits;
    static int max_credits;

public:

    /* randomly generates a new tag and updates the new_tag variable,
     * returns false if there are no more credits */
    static bool request_tag (uint32_t * new_tag);

    /* removes the tag from the set,
     * returned_credits is used by PSL response interface */
    static void release_tag (uint32_t tag, int returned_credits);

    /* removes the tag from the set, returned_credit default to be 1 */
    static void release_tag (uint32_t tag);

    /* checks to make see if the tag exists in the tags_in_use set */
    static bool is_in_use (uint32_t tag);

    /* sets max_credits and reset num_credits to max_credits,
     * should never be called while AFU is in running state */
    static void set_max_credits (int mc);

    /* releases all tags requested */
    static void reset ();

};

#endif
