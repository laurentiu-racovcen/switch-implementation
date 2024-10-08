#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import numpy
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
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
    # 0x8100 for the Ethertype for 802.1Q
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

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

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

    # Initialize MAC address -> Port Table
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

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # ----- Forwarding with learning Implementation ----- #

        # Add entry in MAC table
        mac_table[src_mac] = interface
        # print(mac_table)

        src_int_name = get_interface_name(mac_table[src_mac])
        src_int_vlan = interface_vlan[src_int_name]

        if is_mac_unicast(dest_mac):
            # print("IT'S UNICAST\n")
            if dest_mac in mac_table.keys():
                # Check if the frame is permitted to be forwarded

                # print("dest MAC exists in the mac table! Checking for VLAN...\n")

                dst_int_name = get_interface_name(mac_table[dest_mac])
                dst_int_vlan = interface_vlan[dst_int_name]

                # print("ether type = ")
                # print(ethertype)

                # print("src vlan = ")
                # print(src_int_vlan)

                # print("dst vlan = ")
                # print(dst_int_vlan)

                if src_int_vlan == 'T':
                    # print("HAS VLAN TAG")
                    # The frame is VLAN-tagged (the frame comes from a trunk interface)

                    if dst_int_vlan == 'T':
                        # The destination interface is of trunk type, forward the same frame
                        send_to_link(mac_table[dest_mac], data, length)
                    else:
                        # check if the src host has the same VLAN as the dst host

                        # extract the src vlan id from the frame
                        src_host_vlan_id = data[14:16]
                        
                        if int.from_bytes(src_host_vlan_id, "big") == (ord(dst_int_vlan) - ord('0')):
                            # The destination interface is of access type, and the VLANs are the same
                            # so remove the dot1q field and send the frame
                            new_frame = data[0:12] + data[16:]
                            send_to_link(mac_table[dest_mac], new_frame, length - 4)
                        # else drop the packet
                else:
                    # The frame is NOT VLAN-tagged (the frame comes from an access interface)

                    # If the destination interface is of trunk type, add the dot1q header
                    # and send the frame
                    if dst_int_vlan == 'T':
                        new_frame = data[0:12] + bytearray(struct.pack(">HH", 0x8200, ord(src_int_vlan)-ord('0'))) + data[12:14] + data[14:]
                        send_to_link(mac_table[dest_mac], new_frame, length + 4)
                    elif src_int_vlan == dst_int_vlan:
                        # If the destination interface has the same VLAN id as the source interface
                        # do not add the dot1q header
                        if src_int_vlan == dst_int_vlan:
                            # Forward the same frame to the corresponding interface
                            send_to_link(mac_table[dest_mac], data, length)
                        # else drop the frame                

                # send_to_link(mac_table[dest_mac], data, length)
                # print("the packet has been forwarded!\n")
            else:
                # Send the frame to all the other interfaces within the same VLAN
                for k in interfaces:
                    if (k != interface):
                        if interface_vlan[src_int_name] == 'T':
                            # the src interface is of trunk type
                            if interface_vlan[get_interface_name(k)] == 'T':
                                # dst interface is of trunk type
                                # send unchanged frame
                                send_to_link(k, data, length)

                                # print("The frame has been sent to interface:")
                                # print(get_interface_name(k))
                            else:
                                # dst interface is of access type
                                # remove the VLAN tag and send the frame to host
                                new_frame = data[0:12] + data[16:]
                                vlan_id = data[14:16]
                                if int.from_bytes(vlan_id, "big") == (ord(interface_vlan[get_interface_name(k)]) - ord('0')):
                                    send_to_link(k, new_frame, length - 4)
                                    # print("The frame has been sent to interface:")
                                    # print(get_interface_name(k))
                        else:
                            # the src interface is of access type
                            if interface_vlan[get_interface_name(k)] == 'T':
                                # dst interface is of trunk type
                                # add the dot1q header
                                new_size = data[13] + 4
                                new_frame = data[0:12] + bytearray(struct.pack(">HH", 0x8200, ord(src_int_vlan)-ord('0'))) + data[12:14] + data[14:]
                                send_to_link(k, new_frame, length + 4)
                                # print("The frame has been sent to interface:")
                                # print(get_interface_name(k))
                            else:
                                # dst interface is of access type
                                if src_int_vlan == interface_vlan[get_interface_name(k)]:
                                    # send unchanged frame to host
                                    send_to_link(k, data, length)

                                    # print("The frame has been sent to interface:")
                                    # print(get_interface_name(k))

        else:
            # print("IT'S NOT UNICAST. Sending to all the other interfaces within the same VLAN...\n")

            # Send the frame to all the other interfaces with the same VLAN
            for k in interfaces:
                if (k != interface):

                    if interface_vlan[src_int_name] == 'T':
                        # the src interface is of trunk type
                        if interface_vlan[get_interface_name(k)] == 'T':
                            # dst interface is of trunk type
                            # send unchanged frame
                            send_to_link(k, data, length)

                            # print("The frame has been sent to interface:")
                            # print(get_interface_name(k))
                        else:
                            # dst interface is of access type
                            # remove the VLAN tag and send the frame to host
                            new_frame = data[0:12] + data[16:]
                            vlan_id = data[14:16]
                            if int.from_bytes(vlan_id, "big") == (ord(interface_vlan[get_interface_name(k)]) - ord('0')):
                                send_to_link(k, new_frame, length - 4)

                                # print("The frame has been sent to interface:")
                                # print(get_interface_name(k))
                    else:
                        # the src interface is of access type
                        if interface_vlan[get_interface_name(k)] == 'T':
                            # dst interface is of trunk type
                            # add the dot1q header
                            new_size = data[13] + 4
                            new_frame = data[0:12] + bytearray(struct.pack(">HH", 0x8200, ord(src_int_vlan)-ord('0'))) + data[12:14] + data[14:]
                            send_to_link(k, new_frame, length + 4)

                            # print("The frame has been sent to interface:")
                            # print(get_interface_name(k))
                        else:
                            # dst interface is of access type
                            if src_int_vlan == interface_vlan[get_interface_name(k)]:
                                # send unchanged frame to host
                                send_to_link(k, data, length)

                                # print("The frame has been sent to interface:")
                                # print(get_interface_name(k))

        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
