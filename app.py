import streamlit as st
import sqlite3
import bcrypt
import datetime
import os
from pathlib import Path
import pandas as pd
import secrets
import string
import calendar

# --- Setup ---

BASE_DIR = Path.cwd()
UPLOAD_DIR = BASE_DIR / "krizeeraj_uploads"
INVOICE_DIR = UPLOAD_DIR / "invoices"
DOCS_DIR = UPLOAD_DIR / "documents"
INVOICE_DIR.mkdir(parents=True, exist_ok=True)
DOCS_DIR.mkdir(parents=True, exist_ok=True)

# Database setup
conn = sqlite3.connect(str(BASE_DIR / "krizeeraj_app.db"), check_same_thread=False)
c = conn.cursor()

# Create tables if not exist
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_number TEXT UNIQUE,
    password BLOB,
    role TEXT,
    reference_name TEXT,
    reference_position TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_number TEXT UNIQUE,
    issue_date TEXT,
    expiry_date TEXT,
    validity_days INTEGER,
    status TEXT,
    sop_stage TEXT,
    file_path TEXT,
    amount REAL,
    user_file_number TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_number TEXT,
    upload_date TEXT,
    file_name TEXT,
    file_path TEXT,
    status TEXT,
    admin_comment TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    file_number TEXT,
    message TEXT,
    timestamp TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_number TEXT,
    message TEXT,
    read INTEGER DEFAULT 0,
    timestamp TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    action TEXT,
    details TEXT,
    timestamp TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS sop_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_number TEXT,
    step INTEGER,
    status TEXT,
    notes TEXT,
    last_update TEXT
)''')

conn.commit()

# Constants and SOP steps
SOP_STEPS = [
    "Application Submitted",
    "Initial Review",
    "Documents Verified",
    "Compliance Check",
    "Collateral Agreement",
    "Invoice Issued(PF)",
    "Payment Received",
    "Approval of Collateral",
    "Bank KYC",
    "Lending Acc. Set-up",
    "Invoice Issued(CF)",
    "Payment Received",
    "Contract Signed",
    "Disbursement",
    "Closure"
]

SOP_STATUSES = ["Pending", "In Progress", "Completed", "Delayed", "Rejected"]

INVOICE_STATUSES = ["Unpaid", "Paid", "Overdue", "Expired"]

DOCUMENT_STATUSES = ["Under Review", "Approved", "Rejected"]

REFERENCE_POSITIONS = ["Associate", "Client", "Business Partner", "Supplier", "Consultant", "Other"]

# Helper functions

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed)
    except:
        return False

def generate_password(length=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def add_audit_log(user, action, details=""):
    c.execute("INSERT INTO audit_logs (user, action, details, timestamp) VALUES (?, ?, ?, ?)",
              (user, action, details, datetime.datetime.now().isoformat()))
    conn.commit()

def business_days_after(start_date, business_days):
    current_date = start_date
    days_added = 0
    while days_added < business_days:
        current_date += datetime.timedelta(days=1)
        if current_date.weekday() < 5:  # Monday-Friday
            days_added += 1
    return current_date

def calculate_invoice_expiry(issue_date_str, validity_days=6):
    issue_date = datetime.datetime.strptime(issue_date_str, "%Y-%m-%d").date()
    expiry_date = business_days_after(issue_date, validity_days)
    return expiry_date.strftime("%Y-%m-%d")

def create_admin_if_not_exists():
    c.execute("SELECT * FROM users WHERE role='Admin'")
    admin = c.fetchone()
    if not admin:
        # Create default admin
        hashed = hash_password("admin2005")
        c.execute("INSERT INTO users (file_number, password, role, reference_name, reference_position) VALUES (?, ?, ?, ?, ?)",
                  ("admin", hashed, "Admin", "Krizee Raj", "Admin"))
        conn.commit()

def login_user(file_number, password):
    c.execute("SELECT id, password, role, reference_name, reference_position FROM users WHERE file_number=?", (file_number,))
    user = c.fetchone()
    if user and check_password(password, user[1]):
        return {
            "id": user[0],
            "file_number": file_number,
            "role": user[2],
            "reference_name": user[3],
            "reference_position": user[4]
        }
    else:
        return None

def get_user(file_number):
    c.execute("SELECT id, file_number, role, reference_name, reference_position FROM users WHERE file_number=?", (file_number,))
    user = c.fetchone()
    if user:
        return {
            "id": user[0],
            "file_number": user[1],
            "role": user[2],
            "reference_name": user[3],
            "reference_position": user[4]
        }
    return None

def get_user_sop(file_number):
    c.execute("SELECT step, status, notes, last_update FROM sop_progress WHERE file_number=? ORDER BY step", (file_number,))
    data = c.fetchall()
    # If no data for user, initialize
    if not data:
        for i in range(1, len(SOP_STEPS)+1):
            c.execute("INSERT INTO sop_progress (file_number, step, status, notes, last_update) VALUES (?, ?, ?, ?, ?)",
                      (file_number, i, "Pending", "", datetime.datetime.now().isoformat()))
        conn.commit()
        c.execute("SELECT step, status, notes, last_update FROM sop_progress WHERE file_number=? ORDER BY step", (file_number,))
        data = c.fetchall()
    return data

def update_sop_step(file_number, step, status, notes):
    c.execute("UPDATE sop_progress SET status=?, notes=?, last_update=? WHERE file_number=? AND step=?",
              (status, notes, datetime.datetime.now().isoformat(), file_number, step))
    conn.commit()

def get_invoices_for_user(file_number):
    c.execute("SELECT id, invoice_number, issue_date, expiry_date, validity_days, status, sop_stage, amount, file_path FROM invoices WHERE user_file_number=? ORDER BY issue_date DESC", (file_number,))
    return c.fetchall()

def get_documents_for_user(file_number):
    c.execute("SELECT id, file_name, upload_date, status, admin_comment FROM documents WHERE file_number=? ORDER BY upload_date DESC", (file_number,))
    return c.fetchall()

def save_uploaded_file(uploaded_file, folder_path):
    folder_path.mkdir(parents=True, exist_ok=True)
    filename = uploaded_file.name
    filepath = folder_path / filename
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filepath

def add_message(sender, receiver, file_number, message):
    c.execute("INSERT INTO messages (sender, receiver, file_number, message, timestamp) VALUES (?, ?, ?, ?, ?)",
              (sender, receiver, file_number, message, datetime.datetime.now().isoformat()))
    conn.commit()

def get_messages(file_number, viewer_role):
    # Admin sees all messages, user sees own messages
    if viewer_role == "Admin":
        c.execute("SELECT sender, receiver, file_number, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 100")
    else:
        c.execute("SELECT sender, receiver, file_number, message, timestamp FROM messages WHERE file_number=? ORDER BY timestamp DESC", (file_number,))
    return c.fetchall()

def add_notification(file_number, message):
    c.execute("INSERT INTO notifications (file_number, message, read, timestamp) VALUES (?, ?, 0, ?)", (file_number, message, datetime.datetime.now().isoformat()))
    conn.commit()

def get_notifications(file_number=None, unread_only=False):
    if file_number:
        if unread_only:
            c.execute("SELECT id, message, read, timestamp FROM notifications WHERE file_number=? AND read=0 ORDER BY timestamp DESC", (file_number,))
        else:
            c.execute("SELECT id, message, read, timestamp FROM notifications WHERE file_number=? ORDER BY timestamp DESC", (file_number,))
    else:
        if unread_only:
            c.execute("SELECT id, file_number, message, read, timestamp FROM notifications WHERE read=0 ORDER BY timestamp DESC")
        else:
            c.execute("SELECT id, file_number, message, read, timestamp FROM notifications ORDER BY timestamp DESC")
    return c.fetchall()

def mark_notification_read(notification_id):
    c.execute("UPDATE notifications SET read=1 WHERE id=?", (notification_id,))
    conn.commit()

def mark_all_notifications_read(file_number):
    c.execute("UPDATE notifications SET read=1 WHERE file_number=?", (file_number,))
    conn.commit()

# -- Session state init --
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_info" not in st.session_state:
    st.session_state.user_info = None
if "login_error" not in st.session_state:
    st.session_state.login_error = ""
if "page" not in st.session_state:
    st.session_state.page = "login"  # or dashboard
if "lang" not in st.session_state:
    st.session_state.lang = "en"

# Create default admin if missing
create_admin_if_not_exists()

# --- UI Rendering Functions ---

def login_page():
    st.title("Krizee Raj Group - Project Tracking Login")
    st.write("Please login with your File Number and Password")
    if st.session_state.login_error:
        st.error(st.session_state.login_error)
    file_number = st.text_input("File Number")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = login_user(file_number.strip(), password.strip())
        if user:
            st.session_state.logged_in = True
            st.session_state.user_info = user
            st.session_state.page = "dashboard"
            st.session_state.login_error = ""
        else:
            st.session_state.login_error = "Invalid File Number or Password"

def logout():
    st.session_state.logged_in = False
    st.session_state.user_info = None
    st.session_state.page = "login"

def client_dashboard():
    user = st.session_state.user_info
    st.title(f"Welcome {user['file_number']} - Client Dashboard")
    st.button("Logout", on_click=logout)

    # Show SOP Progress
    st.subheader("SOP Progress")
    sop_data = get_user_sop(user['file_number'])
    col1, col2, col3, col4 = st.columns([2,1,3,2])
    with col1:
        st.markdown("**Step**")
    with col2:
        st.markdown("**Status**")
    with col3:
        st.markdown("**Notes**")
    with col4:
        st.markdown("**Last Update**")
    for step, status, notes, last_update in sop_data:
        col1.write(SOP_STEPS[step-1])
        color = {"Pending":"gray", "In Progress":"orange", "Completed":"green", "Delayed":"yellow", "Rejected":"red"}.get(status, "black")
        col2.markdown(f"<span style='color:{color}'>{status}</span>", unsafe_allow_html=True)
        col3.write(notes if notes else "-")
        col4.write(last_update.split("T")[0])

    st.markdown("---")

    # Invoices
    st.subheader("Invoices")
    invoices = get_invoices_for_user(user['file_number'])
    if not invoices:
        st.info("No invoices found.")
    else:
        for inv in invoices:
            (inv_id, inv_num, issue_date, expiry_date, validity_days, status, sop_stage, amount, file_path) = inv
            st.markdown(f"**Invoice #{inv_num}** (Status: {status}, SOP Stage: {sop_stage})")
            st.write(f"Issue Date: {issue_date} | Expiry Date: {expiry_date} (Validity: {validity_days} business days)")
            st.write(f"Amount: ${amount if amount else 'N/A'}")
            if file_path and os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    st.download_button("Download Invoice PDF", f, file_name=os.path.basename(file_path))
            # Days left calculation
            expiry_dt = datetime.datetime.strptime(expiry_date, "%Y-%m-%d").date()
            days_left = (expiry_dt - datetime.date.today()).days
            if days_left >= 0:
                st.success(f"Days Left: {days_left}")
            else:
                st.error("Invoice Expired")

    st.markdown("---")

    # Documents upload
    st.subheader("Upload Documents")
    uploaded_file = st.file_uploader("Upload PDF/JPEG/PNG document", type=["pdf", "jpeg", "jpg", "png"])
    if uploaded_file:
        user_folder = DOCS_DIR / user['file_number']
        path = save_uploaded_file(uploaded_file, user_folder)
        c.execute("INSERT INTO documents (file_number, upload_date, file_name, file_path, status) VALUES (?, ?, ?, ?, ?)",
                  (user['file_number'], datetime.datetime.now().isoformat(), uploaded_file.name, str(path), "Under Review"))
        conn.commit()
        add_notification(user['file_number'], f"Document '{uploaded_file.name}' uploaded for review.")
        add_audit_log(user['file_number'], "Uploaded document", uploaded_file.name)
        st.success("Document uploaded and sent for admin review.")

    # Show documents status
    st.subheader("Your Documents Status")
    docs = get_documents_for_user(user['file_number'])
    if not docs:
        st.info("No documents uploaded.")
    else:
        for doc_id, name, upload_date, status, comment in docs:
            st.write(f"{name} - Uploaded on {upload_date.split('T')[0]} - Status: {status}")
            if comment:
                st.write(f"Admin Comment: {comment}")

    # Messaging
    st.subheader("Messages")
    messages = get_messages(user['file_number'], user['role'])
    for sender, receiver, fn, message, ts in reversed(messages):
        if fn == user['file_number']:
            st.write(f"[{ts.split('T')[0]}] {sender} to {receiver}: {message}")

    new_msg = st.text_area("Send message to Admin")
    if st.button("Send Message"):
        if new_msg.strip():
            add_message(user['file_number'], "Admin", user['file_number'], new_msg.strip())
            add_notification("admin", f"New message from {user['file_number']}")
            add_audit_log(user['file_number'], "Sent message to Admin", new_msg.strip())
            st.success("Message sent.")

def admin_dashboard():
    user = st.session_state.user_info
    st.title(f"Welcome {user['file_number']} - Admin Dashboard")
    st.button("Logout", on_click=logout)

    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
        "Users", "Invoices", "SOP Progress", "Documents",
        "Messages", "Notifications", "Audit Logs", "Analytics", "Settings"
    ])

    with tab1:
        st.subheader("Manage Users")
        # List all users except admin
        c.execute("SELECT file_number, reference_name, reference_position FROM users WHERE role='User'")
        users = c.fetchall()
        for fn, name, pos in users:
            st.write(f"File Number: {fn}, Name: {name}, Position: {pos}")
        st.markdown("---")
        st.write("Create new user")
        new_file = st.text_input("New User File Number")
        new_ref_name = st.text_input("Reference Name")
        new_ref_pos = st.selectbox("Reference Position", REFERENCE_POSITIONS)
        if st.button("Create User"):
            if new_file.strip() == "" or new_ref_name.strip() == "":
                st.error("File Number and Reference Name required")
            else:
                c.execute("SELECT * FROM users WHERE file_number=?", (new_file.strip(),))
                if c.fetchone():
                    st.error("File Number already exists")
                else:
                    pw = generate_password()
                    hashed_pw = hash_password(pw)
                    c.execute("INSERT INTO users (file_number, password, role, reference_name, reference_position) VALUES (?, ?, 'User', ?, ?)",
                              (new_file.strip(), hashed_pw, new_ref_name.strip(), new_ref_pos))
                    conn.commit()
                    st.success(f"User created with password: {pw} (Save this securely)")
                    add_audit_log(user['file_number'], "Created user", new_file.strip())

    with tab2:
        st.subheader("Manage Invoices")
        # Add invoice form
        with st.form("add_invoice_form"):
            inv_num = st.text_input("Invoice Number")
            issue_date = st.date_input("Issue Date", datetime.date.today())
            validity_days = st.number_input("Validity Days (business days)", 1, 60, 6)
            sop_stage = st.selectbox("SOP Stage", SOP_STEPS)
            amount = st.number_input("Amount ($)", 0.0, 1000000.0, 0.0, step=0.01)
            user_select = st.selectbox("Assign to User", [u[0] for u in users])
            invoice_file = st.file_uploader("Upload Invoice PDF", type=["pdf"])
            submit_inv = st.form_submit_button
            submit_inv = st.form_submit_button("Add Invoice")
            if submit_inv:
                if inv_num.strip() == "":
                    st.error("Invoice Number required")
                else:
                    c.execute("SELECT * FROM invoices WHERE invoice_number=?", (inv_num.strip(),))
                    if c.fetchone():
                        st.error("Invoice Number already exists")
                    else:
                        expiry_date = calculate_invoice_expiry(issue_date.strftime("%Y-%m-%d"), validity_days)
                        file_path = ""
                        if invoice_file:
                            save_path = INVOICE_DIR / inv_num.strip()
                            save_path.mkdir(exist_ok=True)
                            file_path = str(save_uploaded_file(invoice_file, save_path))
                        c.execute(
                            "INSERT INTO invoices (invoice_number, issue_date, expiry_date, validity_days, status, sop_stage, file_path, amount, user_file_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (inv_num.strip(), issue_date.strftime("%Y-%m-%d"), expiry_date, validity_days, "Unpaid", sop_stage, file_path, amount, user_select)
                        )
                        conn.commit()
                        add_audit_log(user['file_number'], "Added invoice", f"Invoice {inv_num.strip()} for user {user_select}")
                        add_notification(user_select, f"New invoice {inv_num.strip()} issued.")
                        st.success(f"Invoice {inv_num.strip()} added successfully!")

        st.markdown("---")
        st.subheader("Existing Invoices")
        c.execute("SELECT id, invoice_number, issue_date, expiry_date, validity_days, status, sop_stage, amount, file_path, user_file_number FROM invoices ORDER BY issue_date DESC")
        invoices = c.fetchall()
        if not invoices:
            st.info("No invoices available")
        else:
            for inv in invoices:
                (inv_id, inv_num, issue_date, expiry_date, validity_days, status, sop_stage, amount, file_path, user_fn) = inv
                with st.expander(f"Invoice #{inv_num} for User {user_fn}"):
                    st.write(f"Issue Date: {issue_date} | Expiry Date: {expiry_date} | Validity: {validity_days} business days")
                    st.write(f"Amount: ${amount}")
                    st.write(f"Status: {status} | SOP Stage: {sop_stage}")
                    if file_path and os.path.exists(file_path):
                        with open(file_path, "rb") as f:
                            st.download_button("Download Invoice PDF", f, file_name=os.path.basename(file_path))
                    # Update status and SOP stage
                    with st.form(f"update_invoice_{inv_id}"):
                        new_status = st.selectbox("Update Status", INVOICE_STATUSES, index=INVOICE_STATUSES.index(status))
                        new_sop = st.selectbox("Update SOP Stage", SOP_STEPS, index=SOP_STEPS.index(sop_stage))
                        submitted_update = st.form_submit_button("Update Invoice")
                        if submitted_update:
                            c.execute("UPDATE invoices SET status=?, sop_stage=? WHERE id=?", (new_status, new_sop, inv_id))
                            conn.commit()
                            add_audit_log(user['file_number'], "Updated invoice", f"Invoice {inv_num} status to {new_status}, SOP to {new_sop}")
                            add_notification(user_fn, f"Invoice {inv_num} updated: status {new_status}, SOP stage {new_sop}")
                            st.success("Invoice updated successfully!")

    with tab3:
        st.subheader("SOP Progress Management")
        c.execute("SELECT DISTINCT file_number FROM sop_progress")
        users_with_sop = [row[0] for row in c.fetchall()]
        selected_user = st.selectbox("Select User", users_with_sop)
        if selected_user:
            sop_data = get_user_sop(selected_user)
            for step, status, notes, last_update in sop_data:
                with st.expander(f"{SOP_STEPS[step-1]} (Last updated: {last_update.split('T')[0]})"):
                    new_status = st.selectbox(f"Status for Step {step}", SOP_STATUSES, index=SOP_STATUSES.index(status), key=f"sopstatus_{selected_user}_{step}")
                    new_notes = st.text_area(f"Notes for Step {step}", value=notes, key=f"sopnotes_{selected_user}_{step}")
                    if st.button(f"Update Step {step} for {selected_user}", key=f"updatesop_{selected_user}_{step}"):
                        update_sop_step(selected_user, step, new_status, new_notes)
                        add_audit_log(user['file_number'], "Updated SOP step", f"User {selected_user}, Step {step}, Status {new_status}")
                        add_notification(selected_user, f"SOP Step '{SOP_STEPS[step-1]}' updated to {new_status}")
                        st.success(f"Step {step} updated")

    with tab4:
        st.subheader("Documents Review")
        c.execute("SELECT id, file_number, file_name, upload_date, status, admin_comment, file_path FROM documents ORDER BY upload_date DESC")
        docs = c.fetchall()
        if not docs:
            st.info("No documents uploaded.")
        else:
            for doc in docs:
                (doc_id, fn, name, upload_date, status, comment, file_path) = doc
                with st.expander(f"Document {name} uploaded by {fn} on {upload_date.split('T')[0]} - Status: {status}"):
                    if file_path and os.path.exists(file_path):
                        with open(file_path, "rb") as f:
                            st.download_button("Download Document", f, file_name=name)
                    st.write(f"Admin Comment: {comment if comment else 'None'}")
                    new_status = st.selectbox(f"Update Status for {name}", DOCUMENT_STATUSES, index=DOCUMENT_STATUSES.index(status), key=f"docstatus_{doc_id}")
                    new_comment = st.text_area(f"Admin Comment", value=comment, key=f"doccomment_{doc_id}")
                    if st.button(f"Update Document {name}", key=f"docupdate_{doc_id}"):
                        c.execute("UPDATE documents SET status=?, admin_comment=? WHERE id=?", (new_status, new_comment, doc_id))
                        conn.commit()
                        add_audit_log(user['file_number'], "Updated Document", f"Document {name} status {new_status}")
                        add_notification(fn, f"Your document '{name}' status updated to {new_status}")
                        st.success("Document updated")

    with tab5:
        st.subheader("Messages")
        messages = get_messages("", "Admin")  # Admin sees all
        for sender, receiver, fn, msg, ts in reversed(messages):
            st.write(f"[{ts.split('T')[0]}] {sender} → {receiver} ({fn}): {msg}")
        new_msg_file = st.text_input("File Number to message")
        new_msg_text = st.text_area("Message")
        if st.button("Send Message to Client"):
            if new_msg_file.strip() == "" or new_msg_text.strip() == "":
                st.error("File number and message cannot be empty.")
            else:
                if get_user(new_msg_file.strip()):
                    add_message("Admin", new_msg_file.strip(), new_msg_file.strip(), new_msg_text.strip())
                    add_notification(new_msg_file.strip(), "New message from Admin")
                    add_audit_log(user['file_number'], "Sent message", f"To {new_msg_file.strip()}: {new_msg_text.strip()}")
                    st.success("Message sent.")
                else:
                    st.error("Invalid file number.")

    with tab6:
        st.subheader("Notifications")
        notifs = get_notifications()
        for notif in notifs:
            nid, fn, msg, read, ts = notif
            style = "font-weight:bold;" if read == 0 else "color:gray;"
            st.markdown(f"<p style='{style}'>{ts.split('T')[0]} - {fn}: {msg}</p>", unsafe_allow_html=True)
            if st.button(f"Mark Read {nid}"):
                mark_notification_read(nid)
                st.experimental_rerun()

    with tab7:
        st.subheader("Audit Logs (Last 100)")
        c.execute("SELECT user, action, details, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 100")
        logs = c.fetchall()
        for u, a, d, t in logs:
            st.write(f"[{t.split('T')[0]}] {u}: {a} - {d}")

    with tab8:
        st.subheader("Analytics")
        # Active applications by SOP stage
        c.execute("SELECT sop_stage, COUNT(*) FROM invoices GROUP BY sop_stage")
        stage_counts = c.fetchall()
        st.write("Invoices by SOP Stage:")
        for stage, count in stage_counts:
            st.write(f"{stage}: {count}")

        c.execute("SELECT status, COUNT(*) FROM invoices GROUP BY status")
        status_counts = c.fetchall()
        st.write("Invoices by Status:")
        for status, count in status_counts:
            st.write(f"{status}: {count}")

        c.execute("SELECT status, COUNT(*) FROM documents GROUP BY status")
        doc_status_counts = c.fetchall()
        st.write("Documents by Status:")
        for status, count in doc_status_counts:
            st.write(f"{status}: {count}")

    with tab9:
        st.subheader("Settings")
        st.write("Multi-language support coming soon...")

# Main app control flow

if not st.session_state.logged_in:
    login_page()
else:
    if st.session_state.user_info['role'] == "Admin":
        admin_dashboard()
    else:
        client_dashboard()