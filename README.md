# PyScanner
Python - Network Scanner

```markdown
# Network Scanner

Network Scanner is a Python-based command-line and GUI tool for scanning live hosts on a network and identifying open ports. It also supports service detection for common ports.

## Features

- Scan for live hosts on a specified IP range or subnet.
- Scan for open ports on live hosts.
- Identify common services running on open ports.
- Multithreading support for faster scanning.
- GUI mode for user-friendly interaction. (In Progress)
- Save scan results to a CSV file.

## Prerequisites

Before using the Network Scanner, ensure you have the following prerequisites installed:

- Python (3.7+ recommended)
- Scapy library (`pip install scapy`)
- Tkinter library (for GUI mode, included in Python standard library)

## Usage

### Command-Line Mode

To use the Network Scanner in command-line mode, run the following command:

```bash
python main.py --target-ip <target_ip_range> --output-csv <output_csv_filename>
```

- `--target-ip`: Specify the target IP range or subnet in CIDR notation (e.g., '192.168.0.1/24').
- `--output-csv`: (Optional) Specify the filename to save scan results to in CSV format.

### Interactive Mode

You can also run the Network Scanner in interactive mode by using:

```bash
python main.py --interactive
```

In interactive mode, you can choose options to scan for live hosts, open ports, or open ports with service detection.

### GUI Mode

To launch the GUI mode, use:

```bash
python main.py --gui
```

The GUI allows you to input the target IP range and the number of threads for scanning.

## Examples

- Scan for live hosts and open ports:

```bash
python main.py --target-ip 192.168.0.1/24 --output-csv results.csv
```

- Launch the GUI mode:

```bash
python main.py --gui
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- This tool utilizes the Scapy library for network scanning.
- Special thanks to the Python community for creating and maintaining these amazing libraries.

```
