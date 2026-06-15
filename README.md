# @lowwattlabs/n8n-nodes-clamav

n8n community node for **ClamAV antivirus scanning** — scan files and directories for malware directly from your n8n workflows via clamd TCP socket.

[![npm version](https://img.shields.io/npm/v/@lowwattlabs/n8n-nodes-clamav)](https://www.npmjs.com/package/@lowwattlabs/n8n-nodes-clamav)
[![GitHub](https://img.shields.io/badge/GitHub-lowwattlabs%2Fn8n--nodes--clamav-blue)](https://github.com/lowwattlabs/n8n-nodes-clamav)

## ⚡ Get a License

- **Monthly** — [$15/mo →](https://buy.stripe.com/28E9AS11q1hB5B53NA9bO04)
- **Annual** — [$150/yr →](https://buy.stripe.com/6oUbJ09xWgcv1kP2Jw9bO05)

Self-hosted ClamAV is free. The license covers priority support and commercial deployment.

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

MIT © [Low Watt Labs](https://github.com/lowwattlabs)
