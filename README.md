# PyScanner
Python - Network Scanner

```markdown
# Network Scanner

A simple Python network scanner script that allows you to scan for live hosts, open ports, and identify common services running on those ports. You can run it in both command-line and graphical user interface (GUI) modes.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Mode](#command-line-mode)
  - [GUI Mode](#gui-mode)
- [Contributing](#contributing)
- [License](#license)

## Features

- Scan for live hosts in a specified IP range.
- Scan for open ports on live hosts.
- Identify common services running on open ports.
- Simple and user-friendly GUI mode.
- Multithreaded scanning for faster results.

## Getting Started

### Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.x installed on your system.

### Installation

1. **Clone the Repository**:

   Clone this repository to your local machine:

   ```bash
   git clone https://github.com/your-username/network-scanner.git
   cd network-scanner
   ```

2. **Install Required Libraries**:

   Run the following command to install the required libraries (excluding those that come with Python):

   ```bash
   pip install scapy
   ```

   This will install the `scapy` library.

## Usage

### Command-Line Mode

You can use the script in command-line mode to perform network scans. Here's how to use it:

```bash
python pyscanner.py --target-ip <target_ip_range> --output-csv <output_csv_filename>
```

- Replace `<target_ip_range>` with the IP range you want to scan (e.g., '192.168.0.1/24').
- Replace `<output_csv_filename>` with the desired filename for saving scan results in CSV format.

### GUI Mode

The script also provides a GUI mode for a more user-friendly experience. To run the GUI mode, use the following command:

```bash
python pyscanner.py --gui
```

This will launch a graphical interface where you can input the target IP range and the number of threads for multithreaded scanning.

## Contributing

Contributions are welcome! Please feel free to submit a pull request for any improvements or fixes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
