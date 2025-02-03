# **Switch Implementation**

>This project consists in implementing a switch that has 3 main functionalities: Switching Table, VLAN support, Spanning Tree Protocol (802.1d).
The switch receives its details (priority and interface-VLAN associations) from a configuration file.

The switch can receive frames on any of its ports, and depending on port states, the switch forwards, drops (or, in case of BPDU, it just analyzes) incoming frames. If the switch is the Root Bridge, it can also send BPDU packets to trunk ports. When the switch receives a frame that has the destination MAC address in the MAC Table, it forwards the frame to the destination interface. But when the switch does not have the destination MAC address in the MAC Table, it sends the frame to all the other interfaces in the same VLAN.

To fulfill the given requirements, there have been used the following functions from the `wrapper.py` file: `init()`, `recv_from_any_link()`, `send_to_link()`, `get_switch_mac()`, `get_interface_name()`.

## **Table of contents**

1. ["main" function](#main-function)
2. [Helper functions](#helper-functions)
3. ["wrapper.py" functions](#wrapperpy-functions)

## **"main" function**

**1.** Store the number of interfaces and the MAC of the switch

**2.** Create and start a new thread that deals with sending BPDU

**3.** Declare MAC Table, Interface-VLAN table and the global variables for STP

**4.** Store (interface name - VLAN/T) associations in the `interface_vlan` dictionary and initialize trunk ports state to `BLOCKING`

**5.** The switch considers itself to be the root bridge, so the trunk ports state is changed to `LISTENING`

**6.** The switch continuously receives frames. If the MAC Table contains the frame's MAC destination, it forwards the frame to the port associated with the given destination MAC address; if not - it forwards the frame to all the other interfaces in the same VLAN.

**7.** If the port where the frame was received is in the `BLOCKING` state and the frame does not contain a BPDU packet, the frame is discarded; else - the frame is processed by the switch.


## **Helper functions**

Check functions:
- `"contains_bpdu_packet"` - checks if a frame contains a `BPDU` packet
- `"is_mac_unicast"` - checks if a particular MAC address is unicast

Creating / Parsing functions:

- `"create_vlan_tag"` - creates the VLAN tag using a given VLAN id
- `"get_bpdu_packet"` - creates a BPDU packet using `root_bridge_id`, `root_path_cost`, `own_bridge_id`, `port`
- `"parse_ethernet_header"` - parses the byte array and returns: `dst_mac`, `src_mac`, `ethertype`, `src_vlan_id`

Frame-sending functions:
- `"send_bpdu_every_sec"` - continuously sends frames containing BPDU packets to the trunk ports if the switch is the Root Bridge
- `"send_unicast_frame"` - sends a frame to a specific port, according to the source and destination VLAN type/ID

Processing functions:
- `"process_bpdu_frame"` - function that processes a received BPDU frame

## **wrapper.py functions**
- `"init"` - returns the number of interfaces of the switch
- `"recv_from_any_link"` - receives frames from any switch interface
- `"send_to_link"` - sends a frame to a certain switch interface
- `"get_switch_mac"` - returns the MAC address of the switch
- `"get_interface_name"` - returns the name of a switch interface

​


**(c) Racovcen Laurențiu**
