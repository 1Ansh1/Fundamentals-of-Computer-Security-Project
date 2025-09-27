import tkinter as tk
from tkinter import ttk, scrolledtext

class ApplicationGUI:
    """
    This class handles the entire GUI layout and widget creation.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1000x700")

        # --- Main Frames ---
        top_frame = ttk.Frame(root, padding="10")
        top_frame.pack(side=tk.TOP, fill=tk.X)
        
        middle_frame = ttk.PanedWindow(root, orient=tk.VERTICAL)
        middle_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # --- Top Frame Widgets (Controls) ---
        ttk.Label(top_frame, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.iface_combobox = ttk.Combobox(top_frame, state="readonly")
        self.iface_combobox.pack(side=tk.LEFT, padx=5)

        ttk.Label(top_frame, text="Filter:").pack(side=tk.LEFT, padx=(10, 5))
        self.filter_entry = ttk.Entry(top_frame, width=40)
        self.filter_entry.pack(side=tk.LEFT, padx=5)

        self.start_button = ttk.Button(top_frame, text="Start")
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(top_frame, text="Stop", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(top_frame, text="Clear")
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # --- Middle Frame Widgets (Packet List and Details) ---
        # Packet list (Treeview)
        tree_frame = ttk.Frame(middle_frame)
        columns = ("#", "Time", "Source IP", "Destination IP", "Protocol", "Length")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.column("#", width=60)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        middle_frame.add(tree_frame)

        # Packet details (ScrolledText)
        details_frame = ttk.Frame(middle_frame)
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.details_text.pack(fill=tk.BOTH, expand=True)

        middle_frame.add(details_frame)