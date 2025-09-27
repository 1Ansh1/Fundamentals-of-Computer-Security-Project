import tkinter as tk
from tkinter import ttk, scrolledtext

class ApplicationGUI:
    """
    This class handles the entire GUI layout and widget creation.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1100x700")

        # --- Style Configuration ---
        # This section defines the custom look and feel
        style = ttk.Style()
        style.configure("Treeview",
                        rowheight=25,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                        font=("Segoe UI", 10, "bold"))
        # Define tags for alternating row colors
        # This is the correct way
        

        # --- Main Frames with Padding ---
        top_frame = ttk.Frame(root, padding="10 10 10 5")
        top_frame.pack(side=tk.TOP, fill=tk.X)
        
        middle_frame = ttk.PanedWindow(root, orient=tk.VERTICAL)
        middle_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))
        
        # --- Grouping Widgets in the Top Frame ---
        # Group for interface and filter
        controls_group = ttk.Frame(top_frame)
        controls_group.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Group for buttons
        buttons_group = ttk.Frame(top_frame)
        buttons_group.pack(side=tk.RIGHT)

        # --- Top Frame Widgets (Controls) ---
        ttk.Label(controls_group, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.iface_combobox = ttk.Combobox(controls_group, state="readonly", width=45)
        self.iface_combobox.pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_group, text="Filter:").pack(side=tk.LEFT, padx=(20, 5))
        self.filter_entry = ttk.Entry(controls_group, width=50)
        self.filter_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        self.start_button = ttk.Button(buttons_group, text="Start")
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_group, text="Stop", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(buttons_group, text="Clear")
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # --- Middle Frame Widgets (Packet List and Details) ---
        # Packet list (Treeview)
        tree_frame = ttk.Frame(middle_frame, padding=(0, 5, 0, 0))
        columns = ("#", "Time", "Source IP", "Destination IP", "Protocol", "Length")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.tree.tag_configure('oddrow', background='#f0f0f0')
        self.tree.tag_configure('evenrow', background='white')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120) # Adjusted width
        self.tree.column("#", width=60)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        middle_frame.add(tree_frame, weight=3) # Give more space to the treeview

        # Packet details (ScrolledText)
        details_frame = ttk.Frame(middle_frame, padding=(0, 5, 0, 0))
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, state=tk.DISABLED, font=("Consolas", 9))
        self.details_text.pack(fill=tk.BOTH, expand=True)

        middle_frame.add(details_frame, weight=2) # Give less space to the details view