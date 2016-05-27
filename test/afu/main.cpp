#include <sstream>
#include <stdlib.h>

#include "AFU.h"

using std::string;
using std::stringstream;

int
main (int argc, char *argv[])
{
    if (argc < 3) {
        fprintf (stderr,
                 "Not enough arguments. Usage: ./afu port_number descriptor_file [parity] [jerror]\n");
        exit (1);
    }

    int
    port = 0;

    string descriptor_file (argv[2]);
    bool parity = false;
    bool jerror = false;

    stringstream ss;

    ss << argv[1];
    ss >> port;

    if (argc == 4 && string (argv[3]) == "parity") {
        printf ("MAIN: AFU parity enabled\n");
        parity = true;
    }

    if (argc == 4 && string (argv[3]) == "jerror") {
        printf ("MAIN: AFU will send jerror not running\n");
        jerror = true;
    }

    if (argc == 5 && string (argv[4]) == "jerror") {
        printf ("MAIN: AFU will send jerror not running\n");
        jerror = true;
    }

    AFU afu (port, descriptor_file, parity, jerror);

    afu.start ();
    debug_msg ("main: AFU quitting");
}
