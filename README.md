# secure-login-system
A Python-based secure login and registration system with admin functionality, password hashing, and account lockout protection.

---

# Features
- User registration with **strong password validation**  
- Passwords stored securely using **bcrypt hashing**  
- Login system with **progressive lockout** after failed attempts  
- **Admin login** with commands:
  - `showlogs` → view audit logs  
  - `listusers` → view all registered users  
  - `removeuser <name>` → delete a user account  
- Audit logging of all actions (registrations, logins, failures, admin actions)  

---

# Tutorial
Here’s a quick overview of how the system works:

**Registration**  
- Users must create a username and a strong password.  
- The password must contain at least:  
  - 1 uppercase letter  
  - 1 lowercase letter  
  - 1 number  
  - 1 special character (!@#$%^&*()-_)  
- Usernames are unique (case-insensitive).  

**Login**  
- Users can log in with their registered credentials.  
- After **3 failed attempts**, the account is temporarily locked.  
- Lockout time increases exponentially with repeated failures.  

**Admin Mode**  
- Admins can log in with their credentials.  
- Admins can manage users and view logs through special commands.  

---

# Setup
1. Clone the repository:
git clone https://github.com/gilladi/secure-login-system.git
cd secure-login-system

2. Create a virtual environment and activate it:
- python -m venv venv
- source venv/bin/activate   # macOS/Linux
- venv\Scripts\activate      # Windows

3. Install dependencies:
pip install -r requirements.txt

4. Run the Program:
python secure_login.py

---

# Future Updates
- Add support for multiple admin accounts with different roles  
- Implement password reset via security questions or tokens  
- Export audit logs to a file (CSV/JSON) for external analysis  
- Add account deactivation/reactivation commands for admins  



