UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You must host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## TODO

    ###########################################################
    ##                                                       ##
    ## REPLACE CONTENT OF THIS FILE WITH YOUR PROJECT REPORT ##
    ##                                                       ##
    ###########################################################

Julia Wang 904995934

High level design: the simple router handles all the logic of getting the incoming packets and checking what type of packet ti was IP/ARP and then dispatching a request/reply/etc based off the packet that was incoming. Then the simple router checks for if it is a nat and icmp and inserts entry in nat table. The simple router also calls on arp cache to lookup and see if there is an entry in arp table, else will send arp request. Simple router also calls on routing table lookup function to find the longest matching prefix. Similarly simple router also calls on nat table lookup to see if there is an entry if not inserts one mapping of internal to external ip for icmp id. Arp cache and Nat table will handle deletion of stale entries >30 sec. 

Problems I encountered was just not having a clear understanding of exactly what to change the header fields to and also transferring a large file sometimes works but other times does not or only transmitts a small portion of the file. I was also confused on the whole topology of where to send and what type of packets to send.
