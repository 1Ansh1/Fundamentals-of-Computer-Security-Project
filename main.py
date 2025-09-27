import tkinter as tk
import threading
import queue
# This is the key import for getting detailed interface info
from scapy.all import conf, get_if_list
import io
import contextlib

# Import the backend and frontend classes from the other files
from sniffer_core import PacketSniffer
from sniffer_gui import ApplicationGUI

class SnifferController:
    """
    The main controller class that connects the GUI and the backend sniffer.
    """
    def __init__(self, root):
        self.root = root
        self.packet_queue = queue.Queue()
        
        # This map will store: {"Friendly Name": "Internal Name"}
        self.iface_map = {}
        self.packets_map = {}

        # Initialize backend and frontend
        self.sniffer = PacketSniffer(self.packet_queue)
        self.gui = ApplicationGUI(root)
        
        # Connect GUI actions to controller methods
        self.gui.start_button.config(command=self.start_sniffing)
        self.gui.stop_button.config(command=self.stop_sniffing)
        self.gui.clear_button.config(command=self.clear_capture)
        self.gui.tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        
        # Populate the interface list with user-friendly names
        self.populate_interface_list()
        
        # Start the GUI update loop
        self.update_gui()

    def populate_interface_list(self):
        """
        NEW METHOD: Populates the interface combobox with descriptive names.
        """
        # The conf.ifaces object holds detailed info about each interface
        for iface in conf.ifaces.values():
            # Create a friendly name, including the IP address if available
            friendly_name = f"{iface.description} ({iface.ip})"
            # Store the mapping from the friendly name to the internal name
            self.iface_map[friendly_name] = iface.name

        # Set the combobox values to our list of friendly names
        self.gui.iface_combobox['values'] = list(self.iface_map.keys())
        if self.gui.iface_combobox['values']:
            self.gui.iface_combobox.current(0)

    def start_sniffing(self):
        self.gui.start_button.config(state=tk.DISABLED)
        self.gui.stop_button.config(state=tk.NORMAL)
        
        # Get the selected FRIENDLY name from the GUI
        selected_friendly_name = self.gui.iface_combobox.get()
        # Look up the corresponding INTERNAL name from our map
        interface_internal_name = self.iface_map.get(selected_friendly_name)

        if not interface_internal_name:
            print("Error: Could not find internal name for selected interface.")
            self.stop_sniffing() # Reset buttons
            return

        filter_str = self.gui.filter_entry.get()
        
        # Run the sniffer in a separate thread
        self.sniffing_thread = threading.Thread(
            target=self.sniffer.start,
            args=(interface_internal_name, filter_str),
            daemon=True
        )
        self.sniffing_thread.start()

    def stop_sniffing(self):
        self.sniffer.stop()
        self.gui.start_button.config(state=tk.NORMAL)
        self.gui.stop_button.config(state=tk.DISABLED)

    def clear_capture(self):
        self.gui.tree.delete(*self.gui.tree.get_children())
        self.gui.details_text.config(state=tk.NORMAL)
        self.gui.details_text.delete(1.0, tk.END)
        self.gui.details_text.config(state=tk.DISABLED)
        self.packets_map.clear()

    def update_gui(self):
        try:
            while not self.packet_queue.empty():
                summary_data, full_packet = self.packet_queue.get_nowait()
                row_tag = 'evenrow' if summary_data['id'] % 2 == 0 else 'oddrow'
                item_id = self.gui.tree.insert("", tk.END, values=tuple(summary_data.values()), tags=(row_tag,))
                self.packets_map[item_id] = full_packet
                self.gui.tree.yview_moveto(1)
        finally:
            self.root.after(100, self.update_gui)

    def show_packet_details(self, event):
        selected_item = self.gui.tree.selection()
        if not selected_item:
            return
            
        packet_obj = self.packets_map.get(selected_item[0])
        if packet_obj:
            with io.StringIO() as buf, contextlib.redirect_stdout(buf):
                packet_obj.show()
                details_str = buf.getvalue()

            self.gui.details_text.config(state=tk.NORMAL)
            self.gui.details_text.delete(1.0, tk.END)
            self.gui.details_text.insert(tk.END, details_str)
            self.gui.details_text.config(state=tk.DISABLED)

# --- Main execution block ---
if __name__ == "__main__":
    # Import the library
    from ttkthemes import ThemedTk

    # Use ThemedTk instead of tk.Tk()
    root = ThemedTk(theme="breeze") # <--- APPLY THE THEME HERE

    controller = SnifferController(root)
    root.mainloop()