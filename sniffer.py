import tkinter as tk
from tkinter import ttk, filedialog
import csv
import threading

from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6

# ---------- State flags ----------
running = False     # when False, sniff() should stop (Stop Sniffing button)
paused = False      # when True, packet_callback will ignore packets (Pause/Resume)
packet_data = []
sniff_thread = None

# ---------- GUI SETUP ----------
root = tk.Tk()
root.title("Network Packet Sniffer")
root.geometry("1000x500")

columns = ("No.", "Protocol", "Source", "Destination", "Length", "Info")
tree = ttk.Treeview(root, columns=columns, show="headings", height=20)

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)

tree.pack(fill="both", expand=True)

# ---------- Color Tags ----------
tree.tag_configure("tcp", background="#D1E7DD")     # greenish
tree.tag_configure("udp", background="#FFF3CD")     # yellow
tree.tag_configure("ip", background="#F8D7DA")      # reddish
tree.tag_configure("arp", background="#FFE5B4")     # orange
tree.tag_configure("ipv6", background="#E5D1FF")    # purple


# ---------- PACKET CALLBACK ----------
def packet_callback(packet):
    """
    Called by scapy for every captured packet.
    If paused -> ignore. If running -> process safely (supports ARP and IPv6).
    """
    global paused, packet_data

    # If paused, just ignore incoming packets (do not stop sniff thread)
    if paused:
        return

    try:
        protocol = ""
        src = "-"
        dst = "-"
        info = ""
        tag = ""
        length = len(packet)

        # Determine protocol safely
        if ARP in packet:
            protocol = "ARP"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            tag = "arp"

        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            if TCP in packet:
                protocol = "TCP"
                info = f"{packet[TCP].sport} → {packet[TCP].dport}"
                tag = "tcp"
            elif UDP in packet:
                protocol = "UDP"
                info = f"{packet[UDP].sport} → {packet[UDP].dport}"
                tag = "udp"
            elif ICMP in packet:
                # NOTE: this catches ICMP(v4) in IPv6 rarely; ICMPv6 would need extra layers.
                protocol = "ICMP"
                tag = "ip"
            else:
                protocol = "IPv6"
                tag = "ipv6"

        elif IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            if TCP in packet:
                protocol = "TCP"
                info = f"{packet[TCP].sport} → {packet[TCP].dport}"
                tag = "tcp"
            elif UDP in packet:
                protocol = "UDP"
                info = f"{packet[UDP].sport} → {packet[UDP].dport}"
                tag = "udp"
            elif ICMP in packet:
                protocol = "ICMP"
                tag = "ip"
            else:
                protocol = "IP"
                tag = "ip"
        else:
            # ignore other L2 protocols we don't show
            return

        row_index = len(packet_data) + 1
        row = [row_index, protocol, src, dst, length, info]
        packet_data.append(row)

        # Insert into GUI
        tree.insert("", tk.END, values=row, tags=(tag,))
        tree.yview_moveto(1)

    except Exception as e:
        print("Packet error:", e)


# ---------- SNIFF CONTROL ----------
def sniff_packets():
    try:
        sniff(
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: not running
        )
    except Exception as e:
        print("Sniff error:", e)


def start_sniffing():
    global running, sniff_thread, paused

    if running:
        return

    running = True
    paused = False

    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    start_button.config(text="Sniffing...", state=tk.DISABLED)
    pause_button.config(text="Pause", state=tk.NORMAL)
    stop_button.config(text="Stop Sniffing", state=tk.NORMAL)


def toggle_pause():
    global paused
    if not running:
        return

    paused = not paused
    pause_button.config(text="Resume" if paused else "Pause")


def stop_sniffing():
    """
    Stop sniffing completely: set running False so sniff exits, clear data and
    re-enable Start button.
    """
    global running, paused, packet_data

    running = False
    paused = False

    tree.delete(*tree.get_children())
    packet_data = []

    start_button.config(text="Start Sniffing", state=tk.NORMAL)
    pause_button.config(text="Pause", state=tk.DISABLED)
    stop_button.config(text="Stopped", state=tk.DISABLED)


def save_csv():
    if not packet_data:
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv")]
    )
    if file_path:
        with open(file_path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(columns)
            writer.writerows(packet_data)


# ---------- UI CONTROLS ----------
control_frame = tk.Frame(root)
control_frame.pack(pady=5)

start_button = tk.Button(control_frame, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=0, column=0, padx=5)

pause_button = tk.Button(control_frame, text="Pause", command=toggle_pause, state=tk.DISABLED)
pause_button.grid(row=0, column=1, padx=5)

save_button = tk.Button(control_frame, text="Save to CSV", command=save_csv)
save_button.grid(row=0, column=2, padx=5)

stop_button = tk.Button(control_frame, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED)
stop_button.grid(row=0, column=3, padx=5)

# ---------- MAIN LOOP ----------
root.mainloop()
