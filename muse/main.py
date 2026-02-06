import argparse
import inspect
from pathlib import Path
import base64
import secrets
from getpass import getpass
import sys
import re
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


KDF_ALGORITHM = hashes.SHA256()
KDF_LENGTH = 32
KDF_ITERATIONS = 120000
SALT_LENGTH = 16

MUSE_DIR = Path.home() / ".muse"


def print_(s: str, sep: str = " ", end: str = "\n", flush: bool = False):
    print(s, sep=sep, end=end, file=sys.stderr, flush=flush)


def key_from_password(password: str, salt: bytes):
    kdf = PBKDF2HMAC(algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt, iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def prompt_password(confirm: bool = False):
    password = getpass()
    if confirm:
        password2 = getpass("Confirm password: ")
        if password != password2:
            print_("Passwords do not match")
            return prompt_password(confirm)
    return password


def prompt_yn(question: str):
    print_(question, end=" (y/n): ", flush=True)
    answer = input()
    if answer.lower() == "y":
        return True
    elif answer.lower() == "n":
        return False
    else:
        print_("Invalid answer")
        return prompt_yn(question)


def encrypt(data: str, password: str):
    salt = secrets.token_bytes(SALT_LENGTH)
    key = key_from_password(password, salt)
    f = Fernet(key)
    return salt + f.encrypt(data.encode("utf-8"))


def decrypt(data: bytes, password: str):
    salt = data[:SALT_LENGTH]
    ciphertext = data[SALT_LENGTH:]
    key = key_from_password(password, salt)
    f = Fernet(key)
    return f.decrypt(ciphertext).decode("utf-8")


def encode_str(s: str):
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8")


def decode_str(s: str):
    return base64.urlsafe_b64decode(s.encode("utf-8")).decode("utf-8")


def get_profile_path(profile: str):
    return MUSE_DIR / encode_str(profile)


def create_profile(profile: str, secrets: list[str]):
    MUSE_DIR.mkdir(parents=True, exist_ok=True)
    profile_path = get_profile_path(profile)
    if profile_path.exists():
        print_(f"Profile {profile} already exists")
        return 1
    profile_path.touch()

    return add_secrets(profile, secrets)


def add_secrets(profile: str, secrets: list[str]):
    profile_path = get_profile_path(profile)
    if not profile_path.exists():
        print_(f"Profile {profile} does not exist")
        return 1

    if profile_path.stat().st_size > 0:
        password = prompt_password()
        existing_secrets = decrypt(profile_path.read_bytes(), password).split("\n")
    else:
        password = None
        existing_secrets = []

    if len(secrets) == 0:
        print_("Reading secrets from stdin")
        secrets = [line.strip() for line in sys.stdin]

    remove_regex = re.compile(r"#.*")
    secrets = [remove_regex.sub("", secret) for secret in secrets]
    secrets = [secret for secret in secrets if secret.strip()]

    existing_vars = set(secret.split("=", 1)[0] for secret in existing_secrets)
    for secret in secrets:
        new_var = secret.split("=", 1)[0]
        if new_var in existing_vars:
            print_(f"Variable {new_var} already exists")
            return 1

    new_secrets = existing_secrets + secrets

    if password is None:
        password = prompt_password(confirm=True)

    encrypted_secrets = encrypt("\n".join(new_secrets), password)
    profile_path.write_bytes(encrypted_secrets)
    return 0


def remove_secrets(profile: str, secrets: list[str]):
    profile_path = get_profile_path(profile)
    if not profile_path.exists():
        print_(f"Profile {profile} does not exist")
        return 1

    if len(secrets) == 0:
        if prompt_yn(f"Delete profile {profile}?"):
            profile_path.unlink()
        else:
            print_("Operation cancelled")
        return 0

    if profile_path.stat().st_size == 0:
        print_(f"Profile {profile} is empty")
        return 1

    password = prompt_password()
    existing_secrets = decrypt(profile_path.read_bytes(), password).split("\n")
    existing_secrets_dict: dict[str, str] = {}
    for secret in existing_secrets:
        secret_name, secret_value = secret.split("=", 1)
        existing_secrets_dict[secret_name] = secret_value

    for secret in secrets:
        if secret not in existing_secrets_dict:
            print_(f"Secret {secret} not found in profile {profile}")
            return 1
        del existing_secrets_dict[secret]

    new_secrets = [f"{name}={value}" for name, value in existing_secrets_dict.items()]
    encrypted_secrets = encrypt("\n".join(new_secrets), password)
    profile_path.write_bytes(encrypted_secrets)
    return 0


def list_profiles(profile: str = None):
    if profile:
        profile_path = get_profile_path(profile)
        if not profile_path.exists():
            print_(f"Profile {profile} does not exist")
            return 1

        password = prompt_password()
        secrets = decrypt(profile_path.read_bytes(), password).split("\n")
        for secret in secrets:
            if secret := secret.strip():
                print_(secret.split("=", 1)[0])
    else:
        if MUSE_DIR.exists():
            for profile_path in MUSE_DIR.iterdir():
                if profile_path.is_file():
                    print_(decode_str(profile_path.name))
    return 0


def activate_profile(profile: str):
    return read_profile(profile, activate=True)


def read_profile(profile: str, activate: bool = False):
    profile_path = get_profile_path(profile)
    if not profile_path.exists():
        print_(f"Profile {profile} does not exist")
        return 1

    print_fn = (lambda s: print(f"export {s}")) if activate else print_

    password = prompt_password()
    secrets = decrypt(profile_path.read_bytes(), password).split("\n")
    secret_names = []
    for secret in secrets:
        secret_name = secret.split("=", 1)[0].strip()
        if secret_name:
            secret_names.append(secret_name)
            print_fn(secret)

    if activate:
        print(f"MUSE_ACTIVE_PROFILE={profile_path.name}")
        print(f"MUSE_ACTIVE_PROFILE_SECRETS={','.join(secret_names)}")

    return 0


def deactivate_profile():
    active_profile = os.getenv("MUSE_ACTIVE_PROFILE")
    if not active_profile:
        print_("No active profile")
        return 1

    print_(f"Deactivating profile {decode_str(active_profile)}")
    print("unset MUSE_ACTIVE_PROFILE")
    for secret in os.getenv("MUSE_ACTIVE_PROFILE_SECRETS").split(","):
        if secret.strip():
            print(f"unset {secret.strip()}")
    print("unset MUSE_ACTIVE_PROFILE_SECRETS")
    return 0


def get_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", help="Command to run", required=True)

    activate_parser = subparsers.add_parser("activate", help="Activate a profile")
    activate_parser.add_argument("profile", help="Profile to activate")
    activate_parser.set_defaults(func=activate_profile)

    read_parser = subparsers.add_parser("read", help="Read and print secrets from a profile")
    read_parser.add_argument("profile", help="Profile to read")
    read_parser.set_defaults(func=read_profile)

    create_parser = subparsers.add_parser("create", help="Create a new profile")
    create_parser.add_argument("profile", help="Profile to create")
    create_parser.add_argument("secrets", nargs="*", help="Secrets to add, read from stdin if not provided")
    create_parser.set_defaults(func=create_profile)

    add_parser = subparsers.add_parser("add", help="Add secrets to a profile")
    add_parser.add_argument("profile", help="Profile to add secrets to")
    add_parser.add_argument("secrets", nargs="*", help="Secrets to add, read from stdin if not provided")
    add_parser.set_defaults(func=add_secrets)

    remove_parser = subparsers.add_parser("remove", help="Remove secrets from a profile")
    remove_parser.add_argument("profile", help="Profile to remove secrets from")
    remove_parser.add_argument(
        "secrets",
        nargs="*",
        help="Secret to remove, if unspecified delete whole profile",
    )
    remove_parser.set_defaults(func=remove_secrets)

    deactivate_parser = subparsers.add_parser("deactivate", help="Deactivate a profile")
    deactivate_parser.set_defaults(func=deactivate_profile)

    list_parser = subparsers.add_parser("list", help="List profiles or secrets in a profile")
    list_parser.add_argument("profile", nargs="?", help="Profile to list, if not provided list all profiles")
    list_parser.set_defaults(func=list_profiles)

    return parser.parse_args()


def main():
    args = get_args()
    func_params = inspect.signature(args.func).parameters
    func_args = {k: v for k, v in vars(args).items() if k in func_params}
    return args.func(**func_args)


if __name__ == "__main__":
    main()
