from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(pkt):
    if IP in pkt:
        print("\n--- New Packet ---")
        print(f"Source IP: {pkt[IP].src} -> Destination IP: {pkt[IP].dst}")

        if TCP in pkt:
            print(f"Protocol: TCP | Src Port: {pkt[TCP].sport} -> Dst Port: {pkt[TCP].dport}")
        elif UDP in pkt:
            print(f"Protocol: UDP | Src Port: {pkt[UDP].sport} -> Dst Port: {pkt[UDP].dport}")
        else:
            print(f"Protocol: Other (IP Protocol Number: {pkt[IP].proto})")

        if Raw in pkt:
            print(f"Payload: {bytes(pkt[Raw].load)[:50]}...")  # show first 50 bytes

print("Starting packet sniffer... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, count=100)
print("\nSniffing finished.")
