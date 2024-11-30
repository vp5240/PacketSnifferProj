import tkinter as tk
from tkinter import ttk, filedialog
import pyshark
import threading

class Sniffer:

    def __init__(self, root):
        
        # Tkinter stuff
        self.root = root
        self.root.title("Packet Sniffer (NSSA-290)")
        self.root.geometry("800x500")

        # GUI Stuff
        self.create_widgets()

        # Vars
        self.capturing = False
        self.capture_thread = None
        self.packet_data = []

        self.interface = "wlp2s0" # Default interface - Change this to your interface

        # Filter initing
        self.filter_protocol = ""
        self.filter_src_ip = ""
        self.filter_dst_ip = ""

        # Panels and menu
        self.create_filter_panel()
        self.create_statistics_panel()
        self.create_menu()


    # Dario's code
    def create_widgets(self):
        pass
    
    # Dario's code
    def quit_application(self):
        pass

    # Dario's code
    def start_capture(self):
        pass

    # Dario's code
    def stop_capture(self):
        pass

    # Toni's code
    def create_filter_panel(self):
        pass

    # Toni's code
    def apply_filters(self, reset=False):
        pass

    # Viktor's code - *Copied from Neovim*
    def capture_packets(self):

        # Capture packets using the selected interface
        # Using pyshark to capture packets
        capture = pyshark.LiveCapture(interface=self.interface)

        # This is the packet number for the current capture session
        # It will be used to display the packet number in the GUI
        packet_number = len(self.packet_data) + 1

        # Start capturing packets
        for packet in capture.sniff_continuously():

            # Check if the user has stopped the capture
            if not self.capturing:
                break

            try:
                # Extract information from the packet and display it
                # in the GUI
                protocol = packet.highest_layer
                src = packet.ip.src
                dst = packet.ip.dst
                length = len(packet)

                # Save packet data for storage and filtering
                raw_packet = str(packet)  # Store raw packet data as a string
                self.packet_data.append(
                    (packet_number, protocol, src, dst, length, raw_packet)
                )

                # Check if the packet matches current filters
                matches_protocol = (
                    not self.filter_protocol or protocol.upper() == self.filter_protocol
                )
                matches_src_ip = not self.filter_src_ip or src == self.filter_src_ip
                matches_dst_ip = not self.filter_dst_ip or dst == self.filter_dst_ip

                # Update the GUI if the packet matches the filters
                if matches_protocol and matches_src_ip and matches_dst_ip:

                    # If packet matches the filters, update the GUI
                    self.update_gui(packet_number, protocol, src, dst, length)

                # Update statistics regardless of whether it matches the filter
                # This is to ensure that the statistics are accurate
                # even if the packet is not displayed in the GUI
                # Also update the packet number
                self.update_statistics(protocol)
                packet_number += 1

            except AttributeError:

                # Skip packets without IP attributes
                continue

            except Exception as e:

                # Handle other unexpected stuff
                print(f"Error capturing packet: {e}")
                continue
        

    # Toni's code
    def update_gui(self, no, protocol, src, dst, length):
        pass
    
    # Viktor's code - *Copied from Neovim*
    def show_packet_details(self, event):

        # Get the selected row and display the raw packet data
        # in the details text thing
        selected_item = self.packet_table.selection()  # Get selected row(s)
        if selected_item:
            try:

                # Debug print - Left since I like it in the terminal
                item_values = self.packet_table.item(selected_item[0], "values")
                print(f"Selected Row Values: {item_values}")  # Debug print

                # Convert the no column to a 0-based index
                index = int(item_values[0]) - 1
                print(f"Index in packet_data: {index}")  # Debug print

                # Retrieve the raw packet data from the packet_data list
                if 0 <= index < len(self.packet_data):
                    raw_packet = self.packet_data[index][
                        5
                    ]  # The last element in the tuple
                    print(f"Raw Packet Data: {raw_packet}")  # Debug print

                    # Display the raw packet data in the details text thing
                    self.details_text.delete("1.0", tk.END)  # Clear text
                    self.details_text.insert(
                        tk.END, raw_packet
                    )  # Display the raw packet details
                else:
                    # Handle cases where index is out of bounds
                    self.details_text.delete("1.0", tk.END)
                    self.details_text.insert(
                        tk.END, "Error: Could not retrieve packet details."
                    )
            except Exception as e:

                # Error stuff
                print(f"Error displaying packet details: {e}")  # Debug print
                self.details_text.delete("1.0", tk.END)
                self.details_text.insert(
                    tk.END, "Error: Could not retrieve packet details."
                )

    # Viktor's code
    def create_statistics_panel(self):

        # Frame for statistics
        self.stats_frame = tk.LabelFrame(self.root, text="Statistics", padx=5, pady=5)
        self.stats_frame.pack(fill=tk.X, padx=5, pady=5)

        # Protocol count display
        self.protocol_count_label = tk.Label(
            self.stats_frame, text="Protocols: TCP: 0, UDP: 0, ICMP: 0"
        )
        self.protocol_count_label.pack(side=tk.LEFT, padx=10)

        # Traffic rate display
        self.traffic_rate_label = tk.Label(
            self.stats_frame, text="Traffic Rate: 0 packets/sec"
        )
        self.traffic_rate_label.pack(side=tk.LEFT, padx=10)

    # Viktor's code - *Copied from Neovim*
    def update_statistics(self, protocol):

        # Count the number of packets for each protocol
        # Initialize the protocol count if it does not exist
        if not hasattr(self, "protocol_count"):
            self.protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0}

        # Increment the protocol count
        # Only increment if the protocol is in the dictionary
        # This is to avoid errors when the protocol is not in the dictionary
        # For example, if the packet does not have a protocol attribute
        if protocol in self.protocol_count:
            self.protocol_count[protocol] += 1

        # Update the protocol count label
        # Display the protocol count in the GUI
        protocol_stats = ", ".join(
            f"{key}: {value}" for key, value in self.protocol_count.items()
        )
        self.protocol_count_label.config(text=f"Protocols: {protocol_stats}")

        # Calculate the traffic rate
        # Initialize the packet rate if it does not exist
        # Basically count the number of packets per second
        if not hasattr(self, "packet_rate"):
            self.packet_rate = 0

        self.packet_rate += 1
        self.traffic_rate_label.config(
            text=f"Traffic Rate: {self.packet_rate} packets/sec"
        )

        # Reset the traffic rate every second
        self.root.after(1000, self.reset_packet_rate)
    
    # Viktor's code - *Copied from Neovim*
    # Not really I just typed it out again
    def reset_packet_rate(self):
        self.packet_rate = 0

    # Dario's code
    def create_menu(self):
        pass

    # Dario's code
    def import_pcap(self):
        pass


if __name__ == '__main__':
    root = tk.Tk()
    app = Sniffer(root)
    root.mainloop()