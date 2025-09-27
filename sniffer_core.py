import threading
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

class PacketSniffer:
    """
    This class handles the core sniffing and packet processing logic.
    It runs in a separate thread and communicates with the main thread
    via a queue.
    """
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue
        self.stop_sniffing_event = threading.Event()
        self.packet_count = 0

    def process_packet(self, packet):
        """
        Callback function for Scapy's sniff().
        Parses the packet and puts the relevant data into the queue.
        """
        # We store the full packet object for detailed view later
        packet_full_obj = packet 

        # Extract summary data for the table view
        self.packet_count += 1
        length = len(packet)
        time = datetime.now().strftime("%H:%M:%S.%f")[:-3] # Time with milliseconds

        protocol = "Other"
        source_ip, dest_ip = "", ""

        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
        
        summary_data = {
            "id": self.packet_count,
            "time": time,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "protocol": protocol,
            "length": length
        }
        
        # Put both summary and full object into the queue as a tuple
        self.packet_queue.put((summary_data, packet_full_obj))

    def start(self, interface, filter_str):
        """
        Starts the packet sniffing loop.
        This function is the target for our sniffing thread.
        """
        self.packet_count = 0
        self.stop_sniffing_event.clear()
        
        # The main sniff loop
        sniff(
            iface=interface,
            prn=self.process_packet,
            filter=filter_str,
            stop_filter=lambda p: self.stop_sniffing_event.is_set()
        )

    def stop(self):
        """
        Sets the event to signal the sniffing thread to stop.
        """
        self.stop_sniffing_event.set()