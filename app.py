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


    def create_widgets(self, ):
        pass

    def quit_application(self):
        pass

    def start_capture(self):
        pass

    def stop_capture(self):
        pass

    def create_filter_panel(self):
        pass

    def apply_filters(self, reset=False):
        pass

    def capture_packets(self):
        pass

    def update_gui(self, no, protocol, src, dst, length):
        pass

    def show_packet_details(self, event):
        pass

    def create_statistics_panel(self):
        pass

    def update_statistics(self, protocol):
        pass

    def reset_packet_rate(self):
        pass

    def create_menu(self):
        pass

    def import_pcap(self):
        pass


if __name__ == '__main__':
    root = tk.Tk()
    app = Sniffer(root)
    root.mainloop()