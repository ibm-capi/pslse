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
                 "Not eneough arguments. Usage: ./afu port_number descriptor_file [parity]\n");
        exit (1);
    }

    int
    port = 0;

    string descriptor_file (argv[2]);
    bool parity = false;

    stringstream ss;

    ss << argv[1];
    ss >> port;

    if (argc == 4 && string (argv[3]) == "parity") {
        printf ("MAIN: AFU parity enabled\n");
        parity = true;
    }

    AFU afu (port, descriptor_file, parity);

    afu.start ();
    debug_msg ("main: AFU quitting");
}
