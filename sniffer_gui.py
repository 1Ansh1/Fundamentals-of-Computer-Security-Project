import customtkinter as ctk
from tkinter import ttk
from PIL import Image

class ApplicationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1200x800")

        # --- Configure Grid Layout ---
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # --- Load Icons ---
        try:
            self.start_icon = ctk.CTkImage(Image.open("icons/start.png").resize((20, 20)))
            self.stop_icon = ctk.CTkImage(Image.open("icons/stop.png").resize((20, 20)))
            self.clear_icon = ctk.CTkImage(Image.open("icons/clear.png").resize((20, 20)))
        except (ImportError, FileNotFoundError):
            print("Pillow library not found or icon files are missing. Icons will not be displayed.")
            self.start_icon, self.stop_icon, self.clear_icon = None, None, None

        # --- Top Frame for Controls ---
        top_frame = ctk.CTkFrame(root, corner_radius=10)
        top_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        top_frame.grid_columnconfigure(3, weight=1)

        # --- Control Widgets ---
        self.iface_label = ctk.CTkLabel(top_frame, text="Interface:")
        self.iface_label.grid(row=0, column=0, padx=(10, 5), pady=10)
        self.iface_combobox = ctk.CTkComboBox(top_frame, width=300, state="readonly")
        self.iface_combobox.grid(row=0, column=1, padx=5, pady=10)

        self.filter_label = ctk.CTkLabel(top_frame, text="Filter:")
        self.filter_label.grid(row=0, column=2, padx=(15, 5), pady=10)
        self.filter_entry = ctk.CTkEntry(top_frame, placeholder_text="e.g., tcp port 80", width=300)
        self.filter_entry.grid(row=0, column=3, padx=5, pady=10, sticky="ew")

        # Green for Start
        self.start_button = ctk.CTkButton(top_frame, text="Start", image=self.start_icon, width=100,
                                  fg_color="#28a745", hover_color="#76DB8C")
        self.start_button.grid(row=0, column=4, padx=5, pady=10)

        # Red for Stop
        self.stop_button = ctk.CTkButton(top_frame, text="Stop", image=self.stop_icon, width=100, state="disabled",
                                 fg_color="#dc3545", hover_color="#d95a66")
        self.stop_button.grid(row=0, column=5, padx=5, pady=10)

        # Blue for Clear
        self.clear_button = ctk.CTkButton(top_frame, text="Clear", image=self.clear_icon, width=100,
                                  fg_color="#17a2b8", hover_color="#77C1CC")
        self.clear_button.grid(row=0, column=6, padx=(5, 10), pady=10)

        # --- Main Panes for Packet List and Details ---
        main_panes = ctk.CTkFrame(root, fg_color="transparent")
        main_panes.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        main_panes.grid_rowconfigure(0, weight=3) # Packet list gets more space
        main_panes.grid_rowconfigure(1, weight=2) # Details gets less space
        main_panes.grid_columnconfigure(0, weight=1)

        # --- Packet List (Treeview) ---
        tree_frame = ctk.CTkFrame(main_panes)
        tree_frame.grid(row=0, column=0, pady=(0, 5), sticky="nsew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # --- Style the ttk.Treeview to match the CustomTkinter theme ---
        style = ttk.Style()
        style.theme_use("default") # Use a base theme to build on
        
        # Configure the Treeview colors
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.map('Treeview', background=[('selected', '#2a2d2e')]) # Color of selected row

        # Configure the Treeview Heading colors
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", font=("Calibri", 10, "bold"), relief="flat")
        style.map("Treeview.Heading", background=[('active', '#343638')])

        columns = ("#", "Time", "Source IP", "Destination IP", "Protocol", "Length")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", style="Treeview")
        self.tree.grid(row=0, column=0, sticky="nsew")

        # Configure tags for row and protocol colors
        self.tree.tag_configure('oddrow', background='#343638')
        self.tree.tag_configure('evenrow', background='#2b2b2b')
        self.tree.tag_configure('TCP', foreground='#66b3ff')
        self.tree.tag_configure('UDP', foreground='#ffcc66')
        self.tree.tag_configure('ICMP', foreground='#ff6666')
        self.tree.tag_configure('Other', foreground='#cccccc')
        
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.column("#", width=60, anchor="center")
        self.tree.column("Time", width=100, anchor="center")
        self.tree.column("Protocol", width=80, anchor="center")
        self.tree.column("Length", width=80, anchor="center")

        scrollbar = ctk.CTkScrollbar(tree_frame, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # --- Packet Details (Textbox) ---
        self.details_text = ctk.CTkTextbox(main_panes, state="disabled", corner_radius=6, font=("Consolas", 16))
        self.details_text.grid(row=1, column=0, pady=(5, 0), sticky="nsew")