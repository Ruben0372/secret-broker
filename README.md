# Secret Broker

**Zero-dependency secrets management for macOS using the built-in Keychain.**

Stop storing API keys in `.env` files. Secret Broker loads credentials from macOS Keychain into environment variables at runtime. No plaintext secrets on disk, ever.

```
┌─────────────────────────────┐
│   Your App / Agent / CI     │
│   reads $OPENAI_API_KEY     │  <-- normal env var access
│   reads $GITHUB_TOKEN       │
└──────────────┬──────────────┘
               │ source load-secrets.sh
┌──────────────▼──────────────┐
│     load-secrets.sh         │
│  loops SECRETS registry     │  <-- lightweight bash wrapper
│  calls macOS `security` CLI │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│     macOS Keychain          │
│  encrypted at rest          │  <-- OS-level vault (AES-256)
│  access-controlled          │
└─────────────────────────────┘
```

## Why

- **29 million secrets** leaked on public GitHub in 2025 (GitGuardian)
- AI agents with filesystem access can read every `.env` file in your project
- OWASP moved Sensitive Information Disclosure to #2 in their LLM Top 10
- Your Mac already has an encrypted vault. Use it.

## Quick Start

```bash
# Clone
git clone https://github.com/Ruben0372/secret-broker.git
cd secret-broker

# Add your first secret (prompts for value, never in shell history)
./add-secret.sh OPENAI_API_KEY

# Load all secrets into your shell
source load-secrets.sh

# Verify
echo $OPENAI_API_KEY   # loaded from Keychain, not a file
```

That's it. Two scripts, zero dependencies, works in 30 seconds.

## Usage

### Adding Secrets

```bash
# Interactive (recommended -- value never in shell history)
./add-secret.sh MY_API_KEY

# With inline value (careful: visible in shell history)
./add-secret.sh MY_API_KEY "sk-abc123"
```

`add-secret.sh` does two things:
1. Stores the secret in macOS Keychain (encrypted)
2. Registers it in `load-secrets.sh` so it gets loaded automatically

### Managing Secrets

```bash
# List all registered secrets and their status
./add-secret.sh --list

# Check which secrets are present vs missing
./add-secret.sh --check

# Remove a secret from Keychain and the registry
./add-secret.sh --remove OLD_API_KEY
```

### Loading Secrets

```bash
# Standard load (source before your app starts)
source load-secrets.sh

# Verify mode (prints status of each secret)
source load-secrets.sh --verify

# Dry run (shows what would load without exporting)
source load-secrets.sh --dry-run
```

## Naming Convention

| Keychain Field    | Value                                      |
|-------------------|--------------------------------------------|
| Service Name (-s) | The env var name exactly (e.g. `GITHUB_TOKEN`) |
| Account (-a)      | Your macOS username (`$(whoami)`)           |

One secret = one Keychain entry = one env var. No mapping files, no config, no ambiguity.

## Integration

Add one line before your app starts. Everything downstream reads normal environment variables.

**Shell profile (~/.zshrc):**
```bash
source ~/path/to/load-secrets.sh
```

**Makefile:**
```makefile
run:
	@source ./load-secrets.sh && python app.py
```

**LaunchAgent (background service):**
```xml
<key>ProgramArguments</key>
<array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>source /path/to/load-secrets.sh && exec /path/to/your-app</string>
</array>
```

**Docker entrypoint (for hybrid setups):**
```dockerfile
# Copy the loader and source it
COPY load-secrets.sh /app/
RUN chmod +x /app/load-secrets.sh
CMD ["bash", "-c", "source /app/load-secrets.sh && exec python app.py"]
```

## Migrating From .env Files

Already have a `.env` file? Move everything to Keychain in one shot:

```bash
# Migrate all KEY=VALUE pairs from .env to Keychain
while IFS='=' read -r key value; do
    [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
    value=$(echo "$value" | sed "s/^['\"]//;s/['\"]$//")
    ./add-secret.sh "$key" "$value"
done < .env

# Verify everything migrated
./add-secret.sh --check

# Delete the plaintext file
rm .env
echo "*.env" >> .gitignore
```

## Security Properties

| Property                    | .env Files | Secret Broker |
|-----------------------------|------------|---------------|
| Encrypted at rest           | No         | Yes (AES-256) |
| Visible to filesystem reads | Yes        | No            |
| Safe from AI agent access   | No         | Yes           |
| Survives git clone          | Sometimes  | Never leaks   |
| Access-controlled           | No         | Yes (macOS)   |
| Shell history clean         | Varies     | Yes           |

## OWASP Alignment

Addresses three OWASP Top 10 for LLM Applications (2025) categories:

- **LLM02 -- Sensitive Information Disclosure:** Secrets are not on the filesystem for agents to discover
- **LLM06 -- Excessive Agency:** Agents operate without direct credential access
- **LLM07 -- System Prompt Leakage:** No credentials in config files that might be ingested as context

For the full security analysis, see the [research paper](https://github.com/Ruben0372/case-study-securing-ai-environments).

## Requirements

- macOS (uses the `security` CLI for Keychain access)
- Bash 3.2+ (ships with macOS)
- Nothing else

## Project Structure

```
secret-broker/
  load-secrets.sh    # Source this to load secrets from Keychain
  add-secret.sh      # Add, remove, list, and check secrets
  LICENSE            # Apache 2.0
  README.md          # You are here
```

## Limitations

Secret Broker solves the **storage** problem: secrets live in an encrypted OS vault instead of plaintext files. But it does not solve the **access control** problem.

When you `source load-secrets.sh`, every secret in the registry is exported to the shell environment. Any process in that session, including AI agents, can read **all** of them. There is no per-agent scoping, no "this agent only gets these 3 secrets," and no audit trail of which process read what.

In practical terms:

| What Secret Broker does            | What it does NOT do                        |
|-------------------------------------|--------------------------------------------|
| Removes secrets from disk           | Restrict which secrets an agent can see     |
| Encrypts at rest via Keychain       | Scope secrets per agent or per task         |
| Prevents leaks in git/shell history | Provide agent identity or authentication    |
| Blocks filesystem-level discovery   | Audit which process accessed which secret   |

The agent authenticates as **you** -- your macOS username, your Keychain. If it can run in your shell, it can read everything you loaded.

For most individual developers, this is a massive improvement over `.env` files. But for teams running multiple agents, or for agents that should only see a subset of credentials, you need an access control layer on top of the storage layer.

This is the gap that sandboxed execution environments fill: the agent runs in an isolated VM and only receives the specific secrets you explicitly pass to it. The Keychain stays out of reach.

## Contributing

Found a bug or want to extend Secret Broker to other platforms (Linux keyring, Windows Credential Manager)? PRs welcome.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/linux-keyring`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

## Author

**Ruben Yomenou**

Part of the [Securing AI Environments](https://github.com/Ruben0372/case-study-securing-ai-environments) research project.
