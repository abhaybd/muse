# MUSE

Multi User SEcrets — A lightweight CLI tool for managing encrypted environment variable profiles.

MUSE allows you to store sensitive environment variables (API keys, tokens, credentials) in password-protected, encrypted profiles. When you need them, simply activate a profile to export all its secrets as environment variables in your current shell session.

Concretely, in some systems, (e.g. robot workstations) multiple people often use the same computer/user/codebase to run tasks, e.g. robot experiments.
However, these experiments might require user-specific secrets, such as API keys or tokens. Saving these in a `.env` file is insecure, but copy-pasting them into your terminal every time is inconvenient.
MUSE gets the best of both worlds, allowing you to store user-specific secrets in "profiles", which are encrypted at rest. When needed, these profiles can be activated, and the secrets are exported into the current shell session as environment variables.

## Features

- **Encrypted Storage**: Secrets are encrypted at rest
- **Profile-Based Organization**: User-specific secrets are stored in per-user profies
- **Shell Integration**: Activate profiles to export secrets directly into your shell environment
- **Simple CLI**: Intuitive commands for creating, managing, and activating profiles

## Getting Started

### Installation

MUSE can be run directly from GitHub using `uvx` (no PyPI installation required):

```bash
uvx --from git+https://github.com/abhaybd/muse.git muse --help
```

For convenient usage, add a function to your shell configuration (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
muse() {
    eval "$(uvx --from git+https://github.com/abhaybd/muse.git muse "$@")"
}
```

Note that `eval` is required since the `activate` and `deactivate` commands need to export variables into your active shell session.

### Quick Start

1. **Create a new profile** with some secrets:

    ```bash
    muse create person_1 API_KEY=sk-xxxx DATABASE_URL=postgres://...
    ```

    To avoid your secrets appearing in the bash history, you can also just run `muse create person_1`, which will read secrets from `stdin`.
    When you're done entering secrets (if any) you can finish by sending `<EOF>`, e.g. with `ctrl+D`.

    You'll then be prompted to set a password for the profile.

2. **Activate the profile** to export secrets as environment variables:

    ```bash
    muse activate person_1
    # Enter your password when prompted
    # Your secrets are now available as environment variables!
    echo $API_KEY
    ```

3. **Deactivate** when done to unset the variables:

    ```bash
    muse deactivate
    ```

    Closing the shell session also works.

## Commands

| Command | Description |
|---------|-------------|
| `muse create <profile> [secrets...]` | Create a new profile with optional initial secrets |
| `muse add <profile> [secrets...]` | Add secrets to an existing profile |
| `muse remove <profile> [secrets...]` | Remove specific secrets, or delete the entire profile if no secrets specified |
| `muse list [profile]` | List all profiles, or list secret names within a profile |
| `muse read <profile>` | Print all secrets from a profile without activating it |
| `muse activate <profile>` | Export secrets to the current shell session |
| `muse deactivate` | Unset previously exported secrets in the current shell session |

### Adding Secrets

Secrets can be provided as command-line arguments:

```bash
muse add myproject NEW_SECRET=value ANOTHER_SECRET=value2
```

Or piped from stdin (useful for `.env` files):

```bash
cat .env | muse add myproject
```

Comments (lines starting with `#`) are automatically stripped when reading from stdin.

## Security

- **Encryption**: AES-128-CBC via Fernet
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 120,000 iterations and a random 16-byte salt
- **Storage**: Encrypted profiles stored in `~/.muse/`
- **Memory**: Secrets are only decrypted when needed and exported to environment variables

## License

MIT
