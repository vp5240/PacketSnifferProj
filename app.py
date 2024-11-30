'''
@ASSESSME.USERID: Alcoholics
@ASSESSME.AUTHOR: vp5240, dk9397, tt4004
@ASSESSME.DESCRIPTION: Packet Sniffer
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

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
        #Start and Stop buttons
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(pady=5)

        self.start_button =tk.Button(
            self.button_frame, text="Start Capture",
            command=self.start_capture
        )
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(
            self.button_frame,
            text="Stop Caapture",
            command=self.stop_capture,
            state=tk.DISABLED,
        )
        self.stop_button.grid(row=0, column=1, padx=5)

        self.quit_button = tk.Button(
            self.button_frame, text="Quit",
            command=self.quit_application
        )
        self.quit_button.grid(row=0, column=2, padx=5)


        #Frame to contaain the packet table and scrollbar
        self.packet_table_frame = tk.Frame(self.root)
        self.packet_table_frame.pack(fill=tk.BOTH, expand= True, padx= 5, pady= 5)

        #Scrollbar for the packet table
        self.packet_scrollbar = tk.Scrollbar(
            self.packet_table_frame, orient=tk.VERTICAL
        )
        self.packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        #Table to display packet data
        self.packet_table = ttk.Treeview(
            self.packet_table_frame,
            columns=("No.","Protocol","Source","Destination","Lenght"),
            show="headings",
            yscrollcommand=self.packet_scrollbar.set,
            #Attach scrollbar
        )
        self.packet_table.heading("No.", text="No.")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.heading("Source", text="Source")
        self.packet_table.heading("Destination", text="Destination")
        self.packet_table.heading("Lenght", text="Lenght")
        self.packet_table.column("No.",width=50)
        self.packet_table.pack(side=tk.LEFT, fill=tk.BOTH, expand= True)

        # Configure scrollbar to work with the table

        self.packet_scrollbar.config(command=self.packet_table.yview)

        # Packet Detials Viewer

        self.details_frame =tk.LabelFrame(
            self.root, text="Packet Details", padx= 5, pady= 5
        )
        self.details_frame.pack(fill=tk.BOTH, expand= True, padx= 5 , pady= 5)

        self.details_text = tk.Text(self.details_frame, wrap= tk.WORD, height=10)
        self.details_text.pack(fill=tk.BOTH,expand=True)

        # Event binding for row selection
        self.packet_table.bind("<<TreeviewSelect>>", self.show_packet_details)


    
    # Dario's code
    def quit_application(self):
        self.capturing = False # Stop capturing
        self.root.destroy() # Close the GUI
        

        

            
        

    # Dario's code
    def start_capture(self):
        self.capuring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.packet_data.clear()
        
        self.packet_table.delete(*self.packet_table.get_children())

        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()

    # Dario's code
    def stop_capture(self):
        self.capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    # Toni's code
    def create_filter_panel(self):
        #Filter panel
        self.filter_frame = tk.LabelFrame(self.root, text="Filters", padx= 5, pady= 5)
        self.filter_frame.pack(fill=tk.X, padx= 5, pady= 5)

        tk.Label(self.filter_frame, text="Protocol:").grid(row=0, column=0, padx=5)
        self.protocol_filter = tk.Entry(self.filter_frame,width=10)
        self.protocol_filter.grid(row=0, column=1, padx=5)

        tk.Label(self.filter_frame, text="SourceIP:").grid(row=0, column=2, padx=5)
        self.src_ip_filter = tk.Entry(self.filter_frame,width=15)
        self.src_ip_filter.grid(row=0, column=3, padx=5)

        tk.Label(self.filter_frame, text="DestinationIP:").grid(row=0, column=4, padx=5)
        self.dst_ip_filter = tk.Entry(self.filter_frame,width=15)
        self.src_ip_filter.grid(row=0, column=5, padx=5)

        self.apply_filters_button = tk.Button(
            self.filter_frame, text="Apply Filters", command=self.apply_filters
        )
        self.apply_filters_button.grid(row=0, column=6, padx=5)

        self.reset_filter_button = tk.Button(self.filter_frame, text="Reset Filters", command=lambda: self.apply_filters(reset=True),)
        self.reset_filter_button.grid(row=0, column=7, padx=5)




    # Toni's code
    def apply_filters(self, reset=False):
        #Apply or reset filters and update the packet table
        if reset:
            #Clear filters
            self.filter_protocol = ""
            self.filter_src_ip = ""
            self.filter_dst_ip = ""
            self.protocol_filter.delete(0, tk.END)
            self.src_ip_filter.delete(0, tk.END)
            self.dst_ip_filter.delete(0, tk.END)
        else:
            #Read filters from GUI
            self.filter_protocol = self.protocol_filter.get().strip().upper()
            self.filter_src_ip = self.src_ip_filter.get().strip()
            self.filter_dst_ip = self.dst_ip_filter.get().strip()

        #Clear the table and re-display filtered packets
        self.packet_table.delete(*self.packet_table.get_children())

        for packet in self.packet_data:
            no, protocol, src, dst, lenght, raw_packet = packet

            #Apply filters to previously captured packets
            matches_protocol = (
                not self.filter_protocol or protocol.upper() == self.filter_protocol
            )
            matches_src_ip = not self.filter_src_ip or src == self.filter_src_ip
            matches_dst_ip = not self.filter_dst_ip or dst == self.filter_dst_ip

            if matches_protocol and matches_src_ip and matches_dst_ip:
                #Display the packet
                self.packet_table.insert(
                    "", tk.END, values = (no, protocol, src, dst, lenght)
                )

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
        print(
            f"Updating GUI: No = {no}, Protocol = {protocol}, Src = {src}, Dst = {dst}, Lenght = {length}"
        )
        #Debug code
        self.root.after(
            0, lambda: self.packet_table.insert(
                "", tk.END, values = (no, protocol, src, dst, length)
            ),
        )
    
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
        """"Create a menu for the application."""
        menu_bar = tk.Menu(self.root)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Import.pcap",command=self.import_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Quit",command=self.quit_application)
        menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menu_bar)

    # Dario's code
    def import_pcap(self):
        """"Import packets from a .pcap, .pcapng, or .cap file."""
        file_path = filedialog.askopenfilename(
            title="Open Capture File",
            filetypes=[
                ("Packet Capture Files", "*.pcap *.pcapng *.cap"),
                ("PCAP files", "*.pcaap"),
                ("PCAPNG files", "*.pcapng"),
                ("CAP files", "*.cap"),
            ],
        )
        if not file_path:
            return # User canceled
        
        try:
            self.packet_table.delete(
                *self.packet_table.get_children()
            ) # Clear existing display
            self.packet_data.clear() # Clear existing packet storaage

            capture = pyshark.FileCapture(file_path)
            packet_number = 1

            for packet in capture:
                try:
                    # Ensure the packet has an IP layer
                    protocol = packet.highest_layer
                    src = packet.ip.src
                    dst = packet.ip.dst
                    length = len(packet)

                    # Save the packet from filtering adn details

                    raw_packet = str(packet)
                    self.packet_data.append(
                        (packet_number, protocol, src, dst, length, raw_packet)
                    )

                     # Apply current filters
                    matches_protocol = (
                        not self.filter_protocol or protocol.upper() == self.filter_protocol
                    )
                    matches_src_ip = not self.filter_src_ip or src == self.filter_src_ip
                    matches_dst_ip = not self.filter_dst_ip or dst == self.filter_dst_ip

                    if matches_protocol and matches_src_ip and matches_dst_ip:
                        self.update_gui(packet_number, protocol, src, dst, length)

                        #Update statistic
                        self.update_statistics(protocol)
                        packet_number += 1

                except AttributeError:
                    # Skip packets without IP attributes
                    continue

                capture.close()  #Ensure file is closed after reading

        except Exception as e:
            print(f"Error importing file:{e}")



if __name__ == '__main__':
    root = tk.Tk()
    app = Sniffer(root)
    root.mainloop()