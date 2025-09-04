from db import init_db
from auth import register_user, login_user, login_admin, show_logs, remove_user, list_users

def print_banner():
    print("=" * 40)
    print(" 🔐  Secure Login System ")
    print("=" * 40)

def main():
    init_db()
    print_banner()

    while True:
        print("\nOptions:")
        print(" [1] Register")
        print(" [2] Login")
        print(" [3] Admin Login")
        print(" [4] Quit")

        choice = input("Choose an option: ").strip().lower()
        if choice in ["1", "register"]:
            username = input("\nUsername: ")
            password = input("Password: ")
            register_user(username, password)

        elif choice in ["2", "login"]:
            username = input("\nUsername: ")
            password = input("Password: ")
            login_user(username, password)

        elif choice in ["3", "admin"]:
            username = input("\nAdmin Username: ")
            password = input("Password: ")
            if login_admin(username, password):
                print("✅ Admin login successful.")
                while True: 
                    command = input("Enter admin command (showlogs, removeuser <name>, listusers, logout): ").strip().lower()
                    if command == "showlogs":
                        show_logs()
                    elif command.startswith("removeuser "):
                        _, target = command.split(maxsplit=1)
                        remove_user(target)
                    elif command.lower() == "listusers":
                        list_users()
                    elif command == "logout":
                        break
                    else:
                        print("⚠️ Invalid admin command.")
            else:
                print("❌ Admin login failed.")

        elif choice in ["4", "quit", "exit"]:
            print("\nGoodbye 👋\n")
            break
        else:
            print("⚠️ Invalid choice! Please try again.")


if __name__ == "__main__":
    main()
