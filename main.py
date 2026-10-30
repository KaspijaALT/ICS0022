import argparse
import getpass
import os
import re
import shlex
import subprocess
import sys
import time

from storage import Vault, VaultError

DEFAULT_VAULT = os.path.expanduser("~/.spm/vault.pvlt")
# Labels: 1-64 letters, digits or . _ @ -
LABEL_PATTERN = re.compile(r"[A-Za-z0-9._@-]{1,64}")
MIN_MASTER_LENGTH = 12
CLIPBOARD_SECONDS = 20
SESSION_HELP = "Commands: list | get <label> | copy <label> | add <label> [username] | delete <label> | exit"


def check_label(label):
    if not LABEL_PATTERN.fullmatch(label):
        raise VaultError("Label may only use letters, digits and . _ @ - (max 64 characters).")
    return label


def check_username(username):
    if len(username) > 256 or not username.isprintable():
        raise VaultError("Username must be at most 256 printable characters.")
    return username


def find_entry(vault, label):
    label = check_label(label)
    if label not in vault.entries:
        raise VaultError(f"No entry called '{label}'.")
    return vault.entries[label]


def ask_new_password(prompt, min_length=1):
    # getpass hides what is typed, passwords never go in command arguments
    password = getpass.getpass(prompt)
    if len(password) < min_length:
        raise VaultError(f"Password must be at least {min_length} characters.")
    if getpass.getpass("Repeat password: ") != password:
        raise VaultError("Passwords do not match.")
    return password


def open_vault(vault_path):
    if not os.path.isfile(vault_path):
        raise VaultError("No vault found. Run 'init' first.")
    return Vault.open(vault_path, getpass.getpass("Master password: "))


def copy_to_clipboard(text):
    command = ["pbcopy"] if sys.platform == "darwin" else ["xclip", "-selection", "clipboard"]
    # Sent through stdin so the password does not show up in the process list
    subprocess.run(command, input=text.encode(), check=True)


def add_entry(vault, label, username):
    label = check_label(label)
    username = check_username(username)
    if label in vault.entries:
        raise VaultError(f"'{label}' already exists.")
    password = ask_new_password(f"Password for {label}: ")
    vault.entries[label] = {"username": username, "password": password}
    vault.save()
    print(f"Saved '{label}'.")


def show_entry(vault, label):
    entry = find_entry(vault, label)
    print(f"Label:    {label}")
    print(f"Username: {entry['username']}")
    print("Password: ********")


def copy_entry(vault, label):
    entry = find_entry(vault, label)
    copy_to_clipboard(entry["password"])
    print(f"Password copied. Clipboard will be cleared in {CLIPBOARD_SECONDS} seconds...")
    try:
        time.sleep(CLIPBOARD_SECONDS)
    finally:  # runs even after Ctrl+C
        copy_to_clipboard("")
        print("Clipboard cleared.")


def list_entries(vault):
    if not vault.entries:
        print("Vault is empty.")
    for label, entry in sorted(vault.entries.items()):
        print(f"{label}  ({entry['username']})")


def delete_entry(vault, label):
    find_entry(vault, label)
    del vault.entries[label]
    vault.save()
    print(f"Deleted '{label}'.")


def run_session_command(vault, command, args):
    if command == "list" and not args:
        list_entries(vault)
    elif command == "get" and len(args) == 1:
        show_entry(vault, args[0])
    elif command == "copy" and len(args) == 1:
        copy_entry(vault, args[0])
    elif command == "add" and len(args) in (1, 2):
        add_entry(vault, args[0], args[1] if len(args) == 2 else "")
    elif command == "delete" and len(args) == 1:
        delete_entry(vault, args[0])
    else:
        print(SESSION_HELP)


def cmd_init(args):
    if os.path.exists(args.vault):
        raise VaultError(f"A vault already exists at {args.vault}.")
    master = ask_new_password("New master password: ", MIN_MASTER_LENGTH)
    Vault.create(args.vault, master).lock()
    print(f"Vault created at {args.vault}")


def cmd_unlock(args):
    with open_vault(args.vault) as vault:
        print("Vault unlocked. " + SESSION_HELP)
        while True:
            try:
                # shlex splits like a shell, so "my label" with quotes stays one word
                words = shlex.split(input("spm> "))
            except EOFError:  # Ctrl+D
                break
            except ValueError:
                print("Error: unbalanced quotes.")
                continue
            if not words:
                continue
            if words[0] == "exit":
                break
            try:
                run_session_command(vault, words[0], words[1:])
            except VaultError as error:
                print(f"Error: {error}")
    print("Vault locked.")


def cmd_add(args):
    with open_vault(args.vault) as vault:
        add_entry(vault, args.label, args.username)


def cmd_get(args):
    with open_vault(args.vault) as vault:
        show_entry(vault, args.label)
        if args.copy:
            copy_entry(vault, args.label)


def cmd_list(args):
    with open_vault(args.vault) as vault:
        list_entries(vault)


def cmd_delete(args):
    with open_vault(args.vault) as vault:
        delete_entry(vault, args.label)


def build_parser():
    parser = argparse.ArgumentParser(prog="spm", description="Secure Password Manager")
    parser.add_argument("--vault", default=DEFAULT_VAULT, help="path to the vault file")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)
    commands.add_parser("unlock", help="unlock once and run several commands").set_defaults(func=cmd_unlock)
    commands.add_parser("list", help="list all labels").set_defaults(func=cmd_list)

    add = commands.add_parser("add", help="add a credential")
    add.add_argument("label")
    add.add_argument("--username", "-u", default="")
    add.set_defaults(func=cmd_add)

    get = commands.add_parser("get", help="show a credential, password stays hidden")
    get.add_argument("label")
    get.add_argument("--copy", "-c", action="store_true", help="copy password to clipboard")
    get.set_defaults(func=cmd_get)

    delete = commands.add_parser("delete", help="delete a credential")
    delete.add_argument("label")
    delete.set_defaults(func=cmd_delete)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except VaultError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
