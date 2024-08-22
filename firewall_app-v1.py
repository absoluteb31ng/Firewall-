import tkinter as tk
from tkinter import messagebox
import ipaddress
import logging

logging.basicConfig(level=logging.ERROR)

class InvalidIPAddressError(ValueError):
    pass

class InvalidProtocolError(ValueError):
    pass

class Packet:
    valid_protocols = {"TCP", "UDP", "ICMP", "IP", "HTTP", "HTTPS", "FTP", "SMTP", "DNS", "SSH", "SNMP"}

    def __init__(self, source_ip, destination_ip, protocol):
        self.source_ip = self.validate_ip(source_ip)
        self.destination_ip = self.validate_ip(destination_ip)
        self.protocol = self.validate_protocol(protocol)

    def validate_ip(self, ip):
        try:
            return ipaddress.ip_address(ip)
        except ValueError as e:
            raise InvalidIPAddressError(f"Invalid IP address: {e}")

    def validate_protocol(self, protocol):
        if protocol.upper() not in self.valid_protocols:
            raise InvalidProtocolError(f"Invalid protocol: {protocol}")
        return protocol.upper()

class PacketFilterRule:
    valid_protocols = set(Packet.valid_protocols)
    ALLOW_ACTION = "ALLOW"
    DENY_ACTION = "DENY"

    def __init__(self, source_ips=None, destination_ips=None, protocols=None, action=DENY_ACTION):
        self.source_ips = self.validate_ips(source_ips)
        self.destination_ips = self.validate_ips(destination_ips)
        self.protocols = self.validate_protocols(protocols)
        self.action = self.validate_action(action)

    def validate_ips(self, ips):
        validated_ips = set()
        for ip in ips or []:
            try:
                validated_ips.add(ipaddress.ip_address(ip))
            except ValueError as e:
                raise InvalidIPAddressError(f"Invalid IP address: {e}")
        return validated_ips

    def validate_protocols(self, protocols):
        if protocols:
            invalid_protocols = set(protocols) - self.valid_protocols
            if invalid_protocols:
                raise InvalidProtocolError(f"Invalid protocols: {', '.join(invalid_protocols)}")
            return set(protocols)
        return set()

    def validate_action(self, action):
        if action.upper() not in {self.ALLOW_ACTION, self.DENY_ACTION}:
            raise ValueError(f"Invalid action: {action}")
        return action.upper()

    def matches(self, packet):
        return ((not self.source_ips or packet.source_ip in self.source_ips)
                and (not self.destination_ips or packet.destination_ip in self.destination_ips)
                and (not self.protocols or packet.protocol in self.protocols))

class Firewall:
    DENY_ACTION = "DENY"

    def __init__(self, default_action=DENY_ACTION):
        self.packet_filter_rules = []
        self.default_action = self.validate_action(default_action)

    def add_rule(self, rule):
        self.packet_filter_rules.append(rule)

    def process_packet(self, packet):
        for rule in self.packet_filter_rules:
            try:
                if rule.matches(packet):
                    return rule.action
            except (InvalidIPAddressError, InvalidProtocolError, ValueError) as e:
                logging.error(f"Error in rule: {e}")
        return self.default_action

    def validate_action(self, action):
        if action.upper() not in {PacketFilterRule.ALLOW_ACTION, self.DENY_ACTION}:
            raise ValueError(f"Invalid default action: {action}")
        return action.upper()

class FirewallApp:
    def __init__(self, master):
        self.master = master
        master.title("Firewall GUI")
        master.configure(bg='black')  # Color de fondo negro

        self.create_widgets()

    def create_widgets(self):
        style = {"fg": "white", "bg": "black"}

        # Source IP widgets
        self.source_frame = tk.Frame(self.master, bg="black")
        self.label_source_ip = tk.Label(self.source_frame, text="Source IP:", **style)
        self.label_source_ip.pack()
        self.source_ip_entry = tk.Entry(self.source_frame, width=15)
        self.source_ip_entry.insert(0, "192.168.1.1")
        self.source_ip_entry.pack()
        self.source_frame.pack(pady=5)

        # Destination IP widgets
        self.destination_frame = tk.Frame(self.master, bg="black")
        self.label_destination_ip = tk.Label(self.destination_frame, text="Destination IP:", **style)
        self.label_destination_ip.pack()
        self.destination_ip_entry = tk.Entry(self.destination_frame, width=15)
        self.destination_ip_entry.insert(0, "192.168.1.2")
        self.destination_ip_entry.pack()
        self.destination_frame.pack(pady=5)

        # Protocol widgets
        self.protocol_frame = tk.Frame(self.master, bg="black")
        self.label_protocol = tk.Label(self.protocol_frame, text="Protocol:", **style)
        self.label_protocol.pack()
        self.protocol_var = tk.StringVar(self.master)
        self.protocol_var.set("TCP")  # Valor predeterminado
        self.protocol_dropdown = tk.OptionMenu(self.protocol_frame, self.protocol_var, *Packet.valid_protocols)
        self.protocol_dropdown.pack()
        self.protocol_frame.pack(pady=5)

        # Check Firewall button
        self.button = tk.Button(self.master, text="Check Firewall", command=self.check_firewall, **style)
        self.button.pack()

    def check_firewall(self):
        source_ip = self.source_ip_entry.get()
        destination_ip = self.destination_ip_entry.get()
        protocol = self.protocol_var.get()

        # Disable the button during processing
        self.button.config(state=tk.DISABLED)

        try:
            ipaddress.ip_address(source_ip)
            ipaddress.ip_address(destination_ip)

            packet = Packet(source_ip=source_ip, destination_ip=destination_ip, protocol=protocol)
            result = firewall.process_packet(packet)
            messagebox.showinfo("Firewall Action", f"Firewall action: {result}")
        except ipaddress.AddressValueError as e:
            messagebox.showerror("Invalid Input", f"Invalid IP address: {e}")
        except (InvalidIPAddressError, InvalidProtocolError, ValueError) as e:
            messagebox.showerror("Invalid Input", f"Error processing packet: {e}")
        finally:
            # Enable the button after processing
            self.button.config(state=tk.NORMAL)

if __name__ == "__main__":
    firewall = Firewall()

    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
