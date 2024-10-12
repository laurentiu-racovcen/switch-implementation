#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

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

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
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

    if src_vlan_id == 'T':
        # print("HAS VLAN TAG")
        # The frame is VLAN-tagged (the frame comes from a trunk interface)

        if dst_vlan_id == 'T':
            # The destination interface is of trunk type, forward the same frame
            send_to_link(dst_int, data, length)
        else:
            # check if the src host has the same VLAN as the dst host

            # extract the src vlan id from the frame
            src_host_vlan_id = data[14:16]
            
            if int.from_bytes(src_host_vlan_id, "big") == (ord(dst_vlan_id) - ord('0')):
                # The destination interface is of access type, and the VLANs are the same
                # so remove the dot1q field and send the frame
                new_frame = data[0:12] + data[16:]
                send_to_link(dst_int, new_frame, length - 4)
            # else drop the packet
    else:
        # The frame is NOT VLAN-tagged (the frame comes from an access interface)

        # If the destination interface is of trunk type, add the dot1q header
        # and send the frame
        if dst_vlan_id == 'T':
            new_frame = data[0:12] + bytearray(struct.pack(">HH", 0x8200, ord(src_vlan_id)-ord('0'))) + data[12:14] + data[14:]
            send_to_link(dst_int, new_frame, length + 4)
        elif src_vlan_id == dst_vlan_id:
            # If the destination interface has the same VLAN id as the source interface
            # do not add the dot1q header
            # Forward the same frame to the corresponding interface
            send_to_link(dst_int, data, length)
            # else drop the frame

def main():
    switch_id = sys.argv[1]

    # Init returns the max interface number.
    # Our interfaces are 0, 1, 2, ..., num_interfaces + 1
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    # Initialize (MAC address -> Port) Table
    mac_table = {}

    # ----- VLAN support Implementation ----- #

    # Read configuration file contents
    f = open("configs/switch" + switch_id + ".cfg", "r")

    # For storing interface - VLAN/T associations
    interface_vlan = {}

    priority = f.readline().strip()

    for line in f:
        elements = line.split()
        interface_vlan[elements[0]] = elements[1]

    # print("priority=" + priority + "\n")
    # print(interface_vlan)

    f.close()

    # Process received frames
    while True:
        interface, data, length = recv_from_any_link()
        dst_mac, src_mac, ethertype, src_vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dst_mac = ':'.join(f'{b:02x}' for b in dst_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)
        create_vlan_tag
        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dst_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # Add entry in MAC table
        mac_table[src_mac] = interface
        # print(mac_table)

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

        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
