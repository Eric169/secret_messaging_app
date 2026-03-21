import tkinter as tk
from tkinter import messagebox, simpledialog
from client.client import Client
from common.config import MESSAGE_POLL_INTERVAL

class App(tk.Tk):
    def __init__(self, client: Client):
        super().__init__()
        self.title("Cryptic Client")

        self.geometry("400x300")
        
        self.client = client
        self.client.load_local_identity()
        self.polling_timer = None
        
        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.show_login_page()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_login_page(self):
        self.title("Cryptic Client")
        if self.polling_timer:

            self.after_cancel(self.polling_timer)
            self.polling_timer = None
        
        if self.client.conn:
            try: self.client.conn.close()
            except: pass
            self.client.conn = None
        self.client.username = None
        self.client.private_rsa = None

        self.clear_container()
        
        tk.Label(self.container, text="Login / Register", font=("Arial", 16)).pack(pady=10)
        
        tk.Label(self.container, text="Username:").pack()
        self.user_entry = tk.Entry(self.container)
        self.user_entry.pack(pady=5)
        
        if self.client.username:
            self.user_entry.insert(0, self.client.username)

        tk.Label(self.container, text="Password:").pack()
        self.pass_entry = tk.Entry(self.container, show="*")
        self.pass_entry.pack(pady=5)
        
        btn_frame = tk.Frame(self.container)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Login", command=self.handle_login).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Register", command=self.handle_register).pack(side="left", padx=5)

    def handle_login(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter both username and password")
            return
            
        success, msg = self.client.login(username, password)
        if success:
            messagebox.showinfo("Success", msg)
            self.show_messaging_page()
        else:
            messagebox.showerror("Error", msg)

    def handle_register(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Warning", "Please enter both username and password")
            return
            
        success, msg = self.client.register(username, password)
        if success:
            messagebox.showinfo("Success", msg + " Please login to continue.")
        else:
            messagebox.showerror("Error", msg)

    def show_messaging_page(self):
        self.title(f"Cryptic Client - {self.client.username}")
        self.clear_container()

        self.geometry("600x400")
        
        # Main Layout: Sidebar and Content
        self.sidebar = tk.Frame(self.container, width=150, bg="#f0f0f0")
        self.sidebar.pack(side="left", fill="y", padx=(0, 10))
        
        self.content = tk.Frame(self.container)
        self.content.pack(side="right", fill="both", expand=True)

        # Sidebar: Contact List
        tk.Label(self.sidebar, text="Contacts", font=("Arial", 12, "bold"), bg="#f0f0f0").pack(pady=5)
        self.contact_list = tk.Listbox(self.sidebar)
        self.contact_list.pack(fill="both", expand=True, padx=5, pady=5)
        self.contact_list.bind("<<ListboxSelect>>", self.on_contact_select)
        
        tk.Button(self.sidebar, text="Add Contact", command=self.add_contact_dialog).pack(fill="x", padx=5, pady=5)
        tk.Button(self.sidebar, text="Logout", command=self.show_login_page).pack(side="bottom", fill="x", padx=5, pady=5)

        # Content: Chat History
        self.history_text = tk.Text(self.content, state="disabled", height=15)
        self.history_text.pack(fill="both", expand=True, pady=(0, 10))
        
        # Content: Message Input
        input_frame = tk.Frame(self.content)
        input_frame.pack(fill="x")
        
        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        tk.Button(input_frame, text="Send", command=self.send_message).pack(side="right")

        self.selected_contact = None
        self.update_contacts()
        self.start_polling()

    def update_contacts(self):
        self.contact_list.delete(0, tk.END)
        for contact in self.client.get_local_contacts():
            self.contact_list.insert(tk.END, contact)

    def on_contact_select(self, event):
        selection = self.contact_list.curselection()
        if selection:
            self.selected_contact = self.contact_list.get(selection[0])
            self.refresh_history()

    def refresh_history(self):
        if not self.selected_contact: return
        
        self.history_text.config(state="normal")
        self.history_text.delete("1.0", tk.END)
        
        history = self.client.get_local_history(self.selected_contact)
        for sender, text, timestamp in history:
            tag = "me" if sender == self.client.username else "them"
            self.history_text.insert(tk.END, f"[{timestamp}] {sender}: {text}\n", tag)
        
        self.history_text.tag_config("me", foreground="blue")
        self.history_text.tag_config("them", foreground="green")
        self.history_text.see(tk.END)
        self.history_text.config(state="disabled")

    def send_message(self):
        if not self.selected_contact:
            messagebox.showwarning("Warning", "Please select a contact first")
            return
            
        content = self.msg_entry.get()
        if not content: return
        
        success, msg = self.client.send_secure_message(self.selected_contact, content)
        if success:
            self.msg_entry.delete(0, tk.END)
            self.refresh_history()
        else:
            messagebox.showerror("Error", msg)

    def add_contact_dialog(self):
        target = simpledialog.askstring("Add Contact", "Enter username:")
        if target:
            success, msg = self.client.send_secure_message(target, "Hello! (Contact added)")
            if success:
                self.update_contacts()
            else:
                messagebox.showerror("Error", msg)

    def start_polling(self):
        if self.polling_timer:
            self.after_cancel(self.polling_timer)

        try:
            new_msgs = self.client.fetch_and_store_messages()
            if new_msgs:
                self.refresh_history()
                self.update_contacts()
        except Exception as e:
            print(f"Polling error: {e}")
            
        self.polling_timer = self.after(int(MESSAGE_POLL_INTERVAL * 1000), self.start_polling)

if __name__ == "__main__":
    client = Client()
    app = App(client)
    app.mainloop()
