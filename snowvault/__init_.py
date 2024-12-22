import os
import base64
import hashlib
from cryptography.fernet import Fernet
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from tinydb import TinyDB, Query

# Constants
DB_FILE = "passwords.json"
KEY_ENV_VAR = "PASSWORD_MANAGER_KEY"

# Setup
console = Console()
db = TinyDB(DB_FILE)
User = Query()

# Functions
def get_or_generate_key():
    """Retrieve the encryption key from the OS or generate and store it."""
    key = os.environ.get(KEY_ENV_VAR)
    if not key:
        key = base64.urlsafe_b64encode(Fernet.generate_key()).decode('utf-8')
        os.environ[KEY_ENV_VAR] = key
    return key

def get_cipher():
    """Return a Fernet cipher object using the secure key."""
    key = get_or_generate_key()
    return Fernet(key)

def hash_master_password(password):
    """Hash the master password using SHA-512."""
    return hashlib.sha512(password.encode()).hexdigest()

def add_password(service, raw_password):
    """Encrypt and add a new password to the database."""
    cipher = get_cipher()
    encrypted_password = cipher.encrypt(raw_password.encode()).decode()
    db.insert({"service": service, "password": encrypted_password})
    console.print(f"Password for [bold green]{service}[/bold green] saved successfully!")

def retrieve_password(service):
    """Retrieve and decrypt a password."""
    result = db.search(User.service == service)
    if result:
        encrypted_password = result[0]["password"]
        cipher = get_cipher()
        raw_password = cipher.decrypt(encrypted_password.encode()).decode()
        console.print(f"Password for [bold cyan]{service}[/bold cyan]: [bold]{raw_password}[/bold]")
    else:
        console.print(f"[red]No password found for service:[/red] {service}")

def list_services():
    """List all saved services."""
    table = Table(title="Saved Services")
    table.add_column("Service", style="cyan", no_wrap=True)

    services = {item["service"] for item in db.all()}
    if services:
        for service in services:
            table.add_row(service)
        console.print(table)
    else:
        console.print("[red]No saved services yet![/red]")

# Main Interface
def main():
    console.print("[bold blue]Welcome to the Secure Password Manager[/bold blue]")
    console.print("[bold yellow]Your encryption key is securely managed.[/bold yellow]\n")

    while True:
        console.print("\n[bold green]Menu[/bold green]:")
        console.print("1. Add a Password")
        console.print("2. Retrieve a Password")
        console.print("3. List All Services")
        console.print("4. Exit")
        
        choice = Prompt.ask("\nChoose an option", choices=["1", "2", "3", "4"], default="4")

        if choice == "1":
            service = Prompt.ask("Enter the service name")
            raw_password = Prompt.ask("Enter the password", password=True)
            add_password(service, raw_password)
        elif choice == "2":
            service = Prompt.ask("Enter the service name to retrieve")
            retrieve_password(service)
        elif choice == "3":
            list_services()
        elif choice == "4":
            console.print("[bold red]Goodbye![/bold red]")
            break

if __name__ == "__main__":
    main()
