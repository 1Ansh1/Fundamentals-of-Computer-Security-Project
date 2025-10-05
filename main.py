import customtkinter as ctk
import threading
import queue
from scapy.all import conf
from urllib.parse import unquote
import io
import contextlib
from scapy.all import Raw
from sniffer_core import PacketSniffer
from sniffer_gui import ApplicationGUI

class SnifferController:
    def __init__(self, root):
        self.root = root
        self.packet_queue = queue.Queue()
        self.iface_map = {}
        self.packets_map = {}

        self.gui = ApplicationGUI(root)
        self.sniffer = PacketSniffer(self.packet_queue)

        self.gui.start_button.configure(command=self.start_sniffing)
        self.gui.stop_button.configure(command=self.stop_sniffing)
        self.gui.clear_button.configure(command=self.clear_capture)
        self.gui.tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        
        self.populate_interface_list()
        self.update_gui()

    def populate_interface_list(self):
        for iface in conf.ifaces.values():
            friendly_name = f"{iface.description} ({iface.ip})"
            self.iface_map[friendly_name] = iface.name
        
        self.gui.iface_combobox.configure(values=list(self.iface_map.keys()))
        if self.gui.iface_combobox.cget("values"):
            self.gui.iface_combobox.set(self.gui.iface_combobox.cget("values")[0])

    def start_sniffing(self):
        self.gui.start_button.configure(state="disabled")
        self.gui.stop_button.configure(state="normal")
        
        selected_friendly_name = self.gui.iface_combobox.get()
        interface_internal_name = self.iface_map.get(selected_friendly_name)

        if not interface_internal_name:
            print("Error: Could not find internal name for selected interface.")
            self.stop_sniffing()
            return

        filter_str = self.gui.filter_entry.get()
        
        self.sniffing_thread = threading.Thread(
            target=self.sniffer.start,
            args=(interface_internal_name, filter_str),
            daemon=True
        )
        self.sniffing_thread.start()

    def stop_sniffing(self):
        self.sniffer.stop()
        self.gui.start_button.configure(state="normal")
        self.gui.stop_button.configure(state="disabled")

    def clear_capture(self):
        self.gui.tree.delete(*self.gui.tree.get_children())
        self.gui.details_text.configure(state="normal")
        self.gui.details_text.delete("1.0", "end")
        self.gui.details_text.configure(state="disabled")
        self.packets_map.clear()

    def update_gui(self):
        try:
            while not self.packet_queue.empty():
                summary_data, full_packet = self.packet_queue.get_nowait()
                row_tag = 'evenrow' if summary_data['id'] % 2 == 0 else 'oddrow'
                protocol_tag = summary_data.get('protocol', 'Other')
                item_id = self.gui.tree.insert("", "end", values=tuple(summary_data.values()), tags=(row_tag, protocol_tag))
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
            formatted_credentials = ""
            if packet_obj.haslayer(Raw): # Need to import Raw here or in core
                try:
                    payload = packet_obj[Raw].load.decode('utf-8', 'ignore')
                    header_separator = "\r\n\r\n"
                    if header_separator in payload:
                        header, body = payload.split(header_separator, 1)
                        if 'username=' in body and 'password=' in body:
                            data_parts = body.split('&')
                            credentials = {}
                            for part in data_parts:
                                if '=' in part:
                                    key, value = part.split('=', 1)
                                    credentials[key] = unquote(value)
                            formatted_credentials += "****************************************\n"
                            formatted_credentials += "    PLAINTEXT CREDENTIALS CAPTURED!    \n"
                            formatted_credentials += "****************************************\n"
                            formatted_credentials += f"  Username: {credentials.get('username', 'N/A')}\n"
                            formatted_credentials += f"  Password: {credentials.get('password', 'N/A')}\n"
                            formatted_credentials += "****************************************\n\n"
                except Exception as e:
                    pass
            with io.StringIO() as buf, contextlib.redirect_stdout(buf):
                packet_obj.show()
                full_details_str = buf.getvalue()
            final_details = formatted_credentials + full_details_str
            self.gui.details_text.configure(state="normal")
            self.gui.details_text.delete("1.0", "end")
            self.gui.details_text.insert("end", final_details)
            self.gui.details_text.configure(state="disabled")

# --- Main execution block ---
if __name__ == "__main__":
    ctk.set_appearance_mode("dark") # Set theme to dark
    ctk.set_default_color_theme("blue") # Set accent color

    root = ctk.CTk() # Create the main window using customtkinter
    controller = SnifferController(root)
    root.mainloop()