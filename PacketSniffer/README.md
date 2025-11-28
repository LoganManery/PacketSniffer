# Packet Sniffer with Device Identification

A network packet sniffer that can identify devices on your network.

## Setup

### 1. Database Configuration

You have three options to configure the database connection:

#### Option A: Using appsettings.json (Easiest)

1. Copy the example configuration:
```bash
   cp appsettings.example.json appsettings.json
```

2. Edit `appsettings.json` and add your database password:
```json
   {
     "ConnectionStrings": {
       "PacketSnifferDb": "Host=localhost;Database=packet_sniffer;Username=postgres;Password=YOUR_ACTUAL_PASSWORD"
     }
   }
```

#### Option B: Using Environment Variables (Most Secure)

Set the full connection string:
```bash
# Windows (PowerShell)
$env:PACKETSNIFFER_CONNECTION_STRING="Host=localhost;Database=packet_sniffer;Username=postgres;Password=your_password"

# Linux/macOS
export PACKETSNIFFER_CONNECTION_STRING="Host=localhost;Database=packet_sniffer;Username=postgres;Password=your_password"
```

Or set individual variables:
```bash
# Windows (PowerShell)
$env:PACKETSNIFFER_DB_HOST="localhost"
$env:PACKETSNIFFER_DB_NAME="packet_sniffer"
$env:PACKETSNIFFER_DB_USER="postgres"
$env:PACKETSNIFFER_DB_PASSWORD="your_password"

# Linux/macOS
export PACKETSNIFFER_DB_HOST="localhost"
export PACKETSNIFFER_DB_NAME="packet_sniffer"
export PACKETSNIFFER_DB_USER="postgres"
export PACKETSNIFFER_DB_PASSWORD="your_password"
```

#### Option C: Using .env file (Alternative)

1. Create a `.env` file in the project root:
```
   PACKETSNIFFER_DB_HOST=localhost
   PACKETSNIFFER_DB_NAME=packet_sniffer
   PACKETSNIFFER_DB_USER=postgres
   PACKETSNIFFER_DB_PASSWORD=your_password
```

2. Load it before running (Linux/macOS):
```bash
   set -a
   source .env
   set +a
   sudo dotnet run
```

### 2. Database Setup

Create the database and schema:
```bash
createdb packet_sniffer
psql packet_sniffer < schema.sql
```

### 3. Running the Sniffer
```bash
# Windows (as Administrator)
dotnet run

# Linux/macOS (with sudo)
sudo -E dotnet run  # -E preserves environment variables
```

## Security Notes

- **NEVER** commit `appsettings.json` to version control
- **NEVER** commit `.env` files to version control
- These files are already in `.gitignore` to prevent accidental commits
- Use `appsettings.example.json` as a template for other developers

## Command Line Options
```bash
dotnet run -- [options]

Options:
  -p, --protocol <TCP|UDP|ICMP>  Filter by protocol
  -s, --source <IP>              Filter by source IP address
  -d, --dest <IP>                Filter by destination IP address
  --port <number>                Filter by port number (1-65535)
  -h, --help                     Show help message
```

## Examples
```bash
# Capture all traffic
sudo dotnet run

# Only TCP traffic
sudo dotnet run -- --protocol TCP

# Traffic from a specific IP
sudo dotnet run -- --source 192.168.1.100

# Traffic on port 443 (HTTPS)
sudo dotnet run -- --port 443
```