# @lowwattlabs/n8n-nodes-clamav

n8n community node for **ClamAV antivirus scanning** — scan files and directories for malware directly from your n8n workflows via clamd TCP socket.

## Features

- **SCAN** — scan files/paths for malware
- **INSTREAM** — stream content scanning for large files
- **STATS** — real-time ClamAV daemon statistics
- **Batch directory scan** — scan entire directories recursively
- **Real-time monitor** — watch a directory and auto-scan new/modified files
- Full clamd protocol support over TCP socket

## Install

```bash
npm install @lowwattlabs/n8n-nodes-clamav
```

Or install via **n8n Community Nodes** — search for "ClamAV" in your n8n instance.

## Prerequisites

- ClamAV daemon (`clamd`) running and accessible via TCP
- n8n >= 1.0.0

## Configuration

Add your ClamAV credentials in n8n:

1. Go to **Credentials** → **Add Credential** → **ClamAV API**
2. Enter your clamd host (default: `127.0.0.1`) and port (default: `3310`)

## Usage

### Scan a File

```json
{
  "operation": "scan",
  "path": "/tmp/suspicious-file.exe"
}
```

### Batch Scan a Directory

```json
{
  "operation": "batchScan",
  "path": "/var/uploads",
  "recursive": true
}
```

### Get Daemon Stats

```json
{
  "operation": "stats"
}
```

## License

MIT © Low Watt Labs