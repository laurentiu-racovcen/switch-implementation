#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Initialize the variables for STP
own_bridge_id = 0
root_bridge_id = 0
root_path_cost = 0
root_port = -1

# For storing (interface name -> trunk port state) associations
trunk_port_state = {}

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the 802.1Q Ethertype
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def get_bdpu_packet(root_bridge_id, root_path_cost, bridge_id, port_id):
    return (
        (0).to_bytes(2, "big") +                # Protocol Identifier
        (0).to_bytes(1, "big") +                # Protocol Version Identifier
        (0).to_bytes(1, "big") +                # BPDU Type
        (0).to_bytes(1, "big") +                # Flags
        root_bridge_id.to_bytes(8, "big") +     # Root Identifier
        root_path_cost.to_bytes(4, "big") +     # Root Path Cost
        bridge_id.to_bytes(8, "big") +          # Bridge Identifier
        (0x8000 + port_id).to_bytes(2, "big") + # Port Identifier
        (1).to_bytes(2, "little") +             # Message Age
        (20).to_bytes(2, "little") +            # Max Age
        (2).to_bytes(2, "little") +             # Hello Time
        (15).to_bytes(2, "little") +            # Forward Delay
        (0).to_bytes(8, "big")                  # Padding
    )

def is_bdpu_frame(frame):
    bdpu_mac = int("01:80:C2:00:00:00".replace(":", ""), 16).to_bytes(6, "big")
    if bdpu_mac == frame[:6]:
        print("IS BDPU FRAME!")
        return True
    return False

def send_bdpu_every_sec():
    while True:
        print("root bridge id:")
        print(root_bridge_id)
        print("own bridge id:")
        print(own_bridge_id)
        print("trunks states:")
        print(trunk_port_state)
        if root_bridge_id == own_bridge_id:
            for port in trunk_port_state:
                # Creating BDPU packet
                bdpu_packet = get_bdpu_packet(root_bridge_id, root_path_cost, own_bridge_id, port)

                # Adding LLC header
                llc_packet = 0x42.to_bytes(1, "big") + 0x42.to_bytes(1, "big") + 0x03.to_bytes(1, "big") + bdpu_packet

                # Adding Ethernet header
                dst_mac = int("01:80:C2:00:00:00".replace(":", ""), 16).to_bytes(6, "big")
                src_mac = (0).to_bytes(6, "big")
                eth_frame = dst_mac + src_mac + (len(llc_packet)-8).to_bytes(2, "big") + llc_packet

                print("I am root bridge! Sending BDPU packets to all trunk ports...")
                send_unicast_frame(eth_frame, len(eth_frame), port, -1, -1)
        else:
            print("I am not root bridge!")
        time.sleep(1)

def is_mac_unicast(mac_addr):
    first_byte = mac_addr[:2]
    first_byte_int = int(first_byte, 16)

    # Get the last bit value of the first byte
    last_bit = first_byte_int & 1

    if last_bit == 0:
        return True
    else:
        return False

def send_unicast_frame(data, length, dst_int, src_vlan_id, dst_vlan_id):
    if src_vlan_id == -1:
        # The frame is VLAN-tagged / contains BDPU packet

        if dst_vlan_id == -1:
            # The destination interface is of trunk type, forward the same frame
            send_to_link(dst_int, data, length)
        else:
            # Check if the src host has the same VLAN as the dst host

            # Extract the src vlan id from the frame
            src_host_vlan_id = data[14:16]
            
            if int.from_bytes(src_host_vlan_id, "big") == dst_vlan_id:
                # The destination interface is of access type, and the VLANs are the same,
                # so remove the dot1q field and send the frame
                new_frame = data[0:12] + data[16:]
                send_to_link(dst_int, new_frame, length - 4)
            # else drop the packet
    else:
        # The frame is NOT VLAN-tagged (the frame comes from an access interface)

        # If the destination interface is of trunk type, add the dot1q header
        # and send the tagged frame
        if dst_vlan_id == -1:
            new_frame = data[0:12] + create_vlan_tag(src_vlan_id) + data[12:]
            send_to_link(dst_int, new_frame, length + 4)
        elif src_vlan_id == dst_vlan_id:
            # If the destination interface has the same VLAN id as the source interface
            # do not add the dot1q header
            # Forward the same frame to the corresponding interface
            send_to_link(dst_int, data, length)
            # else drop the frame

def process_bdpu_frame(recv_port, data, length):
    global root_bridge_id, root_path_cost, root_port

    # Extract BDPU data
    frame_root_bridge_id = int.from_bytes(data[22:30], "big")
    frame_root_path_cost = int.from_bytes(data[30:34], "big")
    frame_sender_bridge_id = int.from_bytes(data[34:42], "big")

    print(frame_root_bridge_id)
    print(root_bridge_id)
    print(root_path_cost)

    if frame_root_bridge_id < root_bridge_id:
        if root_bridge_id == own_bridge_id:
            # Block all the trunk ports except the recv port
            for i in trunk_port_state:
                if i != recv_port:
                    trunk_port_state[i] = "BLK"
                    print("The following port has been blocked:")
                    print(get_interface_name(i))

        # Update root_bridge_id and root_path_cost
        root_bridge_id = frame_root_bridge_id
        root_path_cost = frame_root_path_cost + 10
        root_port = recv_port

        if trunk_port_state[root_port] == "BLK":
            # Change port state from BLOCKING to LISTENING
            trunk_port_state[root_port] = "LSN"

        # Update the BPDU frame and send it to all the other ports
        new_bdpu_frame = (data[:30] + root_path_cost.to_bytes(4, "big") +
                          own_bridge_id.to_bytes(8, "big") + data[42:])
        for i in trunk_port_state:
            if i != root_port:
                send_unicast_frame(new_bdpu_frame, len(new_bdpu_frame), i, -1, -1)
                print("The new BPDU packet has been sent to:")
                print(get_interface_name(i))

    elif frame_root_bridge_id == root_bridge_id:
        if (recv_port == root_port) and (frame_root_path_cost + 10 < root_path_cost):
            root_path_cost = frame_root_path_cost + 10
        elif recv_port != root_port:
            # This port does not lead to the root bridge
            if frame_root_path_cost > root_path_cost:
                # so set it to DESIGNATED
                if trunk_port_state[recv_port] != "LSN":
                    trunk_port_state[recv_port] = "LSN"

    elif frame_sender_bridge_id == own_bridge_id:
        # A loop has been detected
        # Blocking recv port
        trunk_port_state[recv_port] = "BLK"

    elif own_bridge_id == root_bridge_id:
        # Change all trunk ports states to LISTENING (DESIGNATED)
        for port in trunk_port_state:
            trunk_port_state[port] = "LSN"
    # Else discard the BPDU frame

def main():
    switch_id = sys.argv[1]

    # Init returns the max interface number.
    # Our interfaces are 0, 1, 2, ..., num_interfaces + 1
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Using STP global variables
    global own_bridge_id, root_bridge_id, root_path_cost, trunk_port_state

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    # Initialize (MAC address -> Port) Table
    mac_table = {}

    # Read configuration file contents
    f = open("configs/switch" + switch_id + ".cfg", "r")

    # For storing (interface name -> VLAN/T) associations
    interface_vlan = {}

    priority = int(f.readline().strip())

    for line in f:
        elements = line.split()
        if elements[1] == 'T':
            # '-1' means trunk interface type in "interface_vlan" dictionary
            interface_vlan[elements[0]] = -1

            # Convert interface name to interface id
            # And initialize trunk ports state to BLOCKING
            for i in interfaces:
                if get_interface_name(i) == elements[0]:
                    trunk_port_state[i] = "BLK"
        else:
            # store the VLAN id as integer, different from '-1'
            interface_vlan[elements[0]] = int(elements[1])

    print("priority=")
    print(priority)
    print(interface_vlan)

    f.close()

    # Initialize the variables for STP
    own_bridge_id = priority
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    print("trunk port states:")
    print(trunk_port_state)

    # The switch is considered to be the root bridge,
    # so the trunk ports state is changed to "DESIGNATED"
    if own_bridge_id == root_bridge_id:
        for port in trunk_port_state:
            trunk_port_state[port] = "LSN"
    print("trunk port states after change:")
    print(trunk_port_state)

    # Process received frames
    while True:
        interface, data, length = recv_from_any_link()

        # Discard the frame if the port is BLOCKED
        if interface in trunk_port_state:
            if trunk_port_state[interface] == "BLK":
                continue

        if (is_bdpu_frame(data)):
            process_bdpu_frame(interface, data, length)
        else:
            dst_mac, src_mac, ethertype, src_vlan_id = parse_ethernet_header(data)

            # Print the MAC src and MAC dst in human readable format
            dst_mac = ':'.join(f'{b:02x}' for b in dst_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            print(f'Destination MAC: {dst_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, interface), flush=True)

            # Add entry in MAC table
            mac_table[src_mac] = interface
            print(mac_table)

            if is_mac_unicast(dst_mac):
                # The MAC address is unicast
                src_int_name = get_interface_name(interface)
                src_vlan_id = interface_vlan[src_int_name]

                if dst_mac in mac_table.keys():
                    dst_int = mac_table[dst_mac]
                    dst_int_name = get_interface_name(dst_int)
                    dst_vlan_id = interface_vlan[dst_int_name]
                    send_unicast_frame(data, length, dst_int, src_vlan_id, dst_vlan_id)
                else:
                    # The destination MAC is NOT in the MAC table
                    # Send the frame to all the other interfaces within the same VLAN
                    for k in interfaces:
                        if (k != interface):
                            dst_int_name = get_interface_name(k)
                            dst_vlan_id = interface_vlan[dst_int_name]
                            send_unicast_frame(data, length, k, src_vlan_id, dst_vlan_id)
            else:
                # The MAC address is multicast
                # Send the frame to all the other interfaces within the same VLAN
                src_int_name = get_interface_name(interface)
                src_vlan_id = interface_vlan[src_int_name]

                for k in interfaces:
                    if (k != interface):
                        dst_int_name = get_interface_name(k)
                        dst_vlan_id = interface_vlan[dst_int_name]
                        send_unicast_frame(data, length, k, src_vlan_id, dst_vlan_id)

if __name__ == "__main__":
    main()
