import argparse
import socket
import ipaddress
import logging
import time
import csv
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import arping, Scapy_Exception
import os

# Global variable to track progress
progress = 0

# Define common services and port mappings
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    # Add more services and port mappings as needed
}

def initialize_logger():
    # Initialize the logger to write log messages to a file
    logging.basicConfig(
        filename="network_scanner.log",
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def port_scan(target_ip, ports, timeout):
    """
    Scan for open ports on a target IP.

    :param target_ip: Target IP address.
    :param ports: List of ports to scan.
    :param timeout: Socket timeout value.
    :return: List of open ports.
    """
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a socket object for TCP/IP
        sock.settimeout(timeout)  # Set the socket timeout
        result = sock.connect_ex((target_ip, port))  # Attempt a connection to the target IP and port
        if result == 0:
            open_ports.append(port)  # If the connection is successful, add the port to the list of open ports
        sock.close()  # Close the socket
    return open_ports  # Return the list of open ports

def save_results_to_csv(live_hosts, csv_filename):
    """
    Save scan results to a CSV file.

    :param live_hosts: List of live hosts with IP and MAC addresses.
    :param csv_filename: Name of the CSV file to save results.
    """
    with open(csv_filename, mode="w", newline="") as csv_file:
        fieldnames = ["IP", "MAC", "Open Ports"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)  # Create a CSV writer
        writer.writeheader()  # Write the CSV header
        for host in live_hosts:  # Loop through live hosts
            open_ports = port_scan(host['ip'], range(1, 1025), timeout=1)  # Scan open ports for the host
            open_ports_str = ", ".join(map(str, open_ports))  # Convert open ports to a string
            writer.writerow({"IP": host['ip'], "MAC": host['mac'], "Open Ports": open_ports_str})  # Write to CSV

def get_local_ip_and_network():
    try:
        # Get the local IP address and network
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a socket object for UDP
        s.connect(("8.8.8.8", 80))  # Connect to a remote host (Google DNS)
        local_ip = s.getsockname()[0]  # Get the local IP address
        s.close()  # Close the socket
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)  # Create an IPv4 network object
        return str(network)  # Return the network as a string
    except Exception as e:
        print(f"Error getting local IP and network: {str(e)}")  # Handle exceptions and print an error message
        return None  # Return None on error

def scan_worker(host, ports, timeout):
    """
    Scan worker function for multithreaded scanning.

    :param host: Dictionary containing IP and MAC address of the host.
    :param ports: List of ports to scan.
    :param timeout: Socket timeout value.
    """
    open_ports = port_scan(host['ip'], ports, timeout)  # Scan open ports for the host
    if open_ports:
        print(f"Open ports on {host['ip']} ({host['mac']}): {', '.join(map(str, open_ports))}")  # Print open ports
        for port in open_ports:  # Loop through open ports
            service = COMMON_SERVICES.get(port, "Unknown")  # Get the service name for the port
            print(f"Port {port}: {service} service")  # Print service information

def scan(target_ip, ports, timeout, num_threads, csv_filename):
    """
    Perform network scanning.

    :param target_ip: Target IP address or range.
    :param ports: List of ports to scan.
    :param timeout: Socket timeout value.
    :param num_threads: Number of threads for multithreaded scanning.
    :param csv_filename: Name of the CSV file to save results.
    """
    if target_ip is None:
        print("Error: Target IP range is not specified.")  # Check if the target IP range is specified
        return  # Return if not specified

    live_hosts = []  # Initialize a list to store live hosts
    try:
        network = ipaddress.IPv4Network(target_ip, strict=False)  # Create an IPv4 network object
        target_ip_range = list(network.hosts())  # Generate a list of IP addresses in the target range

        def discover_live_hosts(start, end):
            for ip in target_ip_range[start:end]:
                response = os.system(f"ping -n 1 -w {timeout * 1000} {ip}")
                if response == 0:
                    try:
                        ans, _ = arping(ip)
                        mac = ans[0][1].src if ans else "Unknown"
                    except Scapy_Exception:
                        mac = "Unknown"
                    live_hosts.append({"ip": str(ip), "mac": mac})

        if num_threads > 1:  # Check if multithreading is enabled
            step = len(target_ip_range) // num_threads  # Calculate the step size for each thread
            threads = []  # Initialize a list to store thread objects
            for i in range(0, len(target_ip_range), step):
                t = threading.Thread(target=discover_live_hosts, args=(i, i + step))
                threads.append(t)  # Create and start threads for discovering live hosts
                t.start()
            for t in threads:
                t.join()  # Wait for all threads to finish
        else:
            discover_live_hosts(0, len(target_ip_range))  # Perform single-threaded discovery

        if live_hosts:
            print("Live hosts found:")
            for host in live_hosts:
                print(f"IP: {host['ip']} | MAC: {host['mac']}")
                time.sleep(1)
                open_ports = port_scan(host['ip'], ports, timeout)
                if open_ports:
                    print(f"Open ports on {host['ip']} ({host['mac']}): {', '.join(map(str, open_ports))}")
                if csv_filename:
                    save_results_to_csv(live_hosts, csv_filename)  # Save results to CSV file if specified
        else:
            print("No live hosts found in the specified range.")  # Print a message if no live hosts found

    except Exception as e:
        logging.exception(f"An error occurred during the network scan: {str(e)}")
        print(f"An error occurred: {str(e)}")  # Handle exceptions and print an error message

def create_gui():
    def scan_button_click():
        target_ip = ip_entry.get()  # Get the target IP range from the GUI input
        try:
            num_threads = int(num_threads_entry.get())  # Get the number of threads from the GUI input
            scan_from_gui(target_ip, num_threads)
        except ValueError:
            # Display an error pop-up for invalid input
            messagebox.showerror("Error", "Invalid number of threads. Please enter a valid integer.")

    def update_progress():
        # Function to update the progress bar
        progress_bar["value"] = progress

    root = tk.Tk()  # Create the root window
    root.title("Network Scanner")  # Set the window title

    frame = ttk.Frame(root)  # Create a frame within the window
    frame.pack(padx=20, pady=20)  # Set padding for the frame

    label = ttk.Label(frame, text="Enter target IP range:")  # Create a label
    label.pack()  # Pack the label into the frame

    ip_entry = ttk.Entry(frame)  # Create an entry widget for target IP
    ip_entry.pack()  # Pack the entry widget into the frame

    num_threads_label = ttk.Label(frame, text="Enter number of threads:")  # Create a label for number of threads
    num_threads_label.pack()  # Pack the label into the frame

    num_threads_entry = ttk.Entry(frame)  # Create an entry widget for number of threads
    num_threads_entry.pack()  # Pack the entry widget into the frame

    button = ttk.Button(frame, text="Scan", command=scan_button_click)  # Create a button with a callback
    button.pack()  # Pack the button into the frame

    # Create a progress bar
    progress_bar = ttk.Progressbar(frame, orient="horizontal", length=200, mode="determinate")
    progress_bar.pack()

    root.after(100, update_progress)  # Update the progress bar every 100 milliseconds

    root.mainloop()  # Start the GUI main loop

def scan_from_gui(target_ip, num_threads):
    try:
        scan(target_ip, ports=range(1, 1025), timeout=1, num_threads=num_threads, csv_filename="results.csv")
    except Exception as e:
        logging.exception(f"An error occurred during the network scan: {str(e)}")
        # Display an error pop-up for the scan error
        messagebox.showerror("Error", f"An error occurred during the network scan: {str(e)}")

def interactive_mode():
    print("Network Scanner - Interactive Mode")
    print("1. Scan for live hosts")
    print("2. Scan for open ports")
    print("3. Scan for open ports with service detection")
    print("4. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        input_string = input("Enter the base IP address (e.g., 192.168.0.1) or IP range (e.g., 192.168.0.1/24): ")
        target_ip = input_string.strip()  # Get the target IP input
        scan(target_ip, ports=range(1, 1025), timeout=1, num_threads=4, csv_filename="results.csv")
    elif choice == "2":
        input_string = input("Enter the base IP address (e.g., 192.168.0.1) or IP range (e.g., 192.168.0.1/24): ")
        target_ip = input_string.strip()  # Get the target IP input
        open_ports = port_scan(target_ip, range(1, 1025), timeout=1)
        print(f"Open ports: {', '.join(map(str, open_ports))}")
    elif choice == "3":
        input_string = input("Enter the base IP address (e.g., 192.168.0.1) or IP range (e.g., 192.168.0.1/24): ")
        target_ip = input_string.strip()  # Get the target IP input
        open_ports = port_scan(target_ip, range(1, 1025), timeout=1)
        print(f"Open ports: {', '.join(map(str, open_ports))}")
        for port in open_ports:
            service = COMMON_SERVICES.get(port, "Unknown")
            print(f"Port {port}: {service} service")
    elif choice == "4":
        print("Exiting.")
    else:
        print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")
    parser.add_argument("--interactive", action="store_true", help="Enter interactive mode")
    parser.add_argument("--target-ip", type=str, help="Target IP range to scan (e.g., '192.168.0.1/24')")
    parser.add_argument("--output-csv", type=str, help="Save results to a CSV file")
    args = parser.parse_args()

    if args.gui:
        create_gui()
    elif args.interactive:
        interactive_mode()
    else:
        scan(args.target_ip, ports=range(1, 1025), timeout=1, num_threads=4, csv_filename=args.output_csv)
