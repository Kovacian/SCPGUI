import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
from scp_core import create_ssh_client, scp_upload
from session_store import save_session, load_session

class SCPGuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SCP Transfer Tool")
        self.file_path = tk.StringVar()
        self.remote_path = tk.StringVar()
        self.username = tk.StringVar()
        self.hostname = tk.StringVar()
        self.port = tk.StringVar(value="22")
        self.password = None
        self.recursive = tk.BooleanVar()

        self.build_ui()
        self.load_session()

    def build_ui(self):
        padding = {'padx': 10, 'pady': 5}

        ttk.Label(self.root, text="Remote Host:").grid(row=0, column=0, **padding)
        ttk.Entry(self.root, textvariable=self.hostname).grid(row=0, column=1, **padding)

        ttk.Label(self.root, text="Port:").grid(row=1, column=0, **padding)
        ttk.Entry(self.root, textvariable=self.port).grid(row=1, column=1, **padding)

        ttk.Label(self.root, text="Username:").grid(row=2, column=0, **padding)
        ttk.Entry(self.root, textvariable=self.username).grid(row=2, column=1, **padding)

        ttk.Button(self.root, text="Enter Password", command=self.prompt_password).grid(row=3, column=1, **padding)

        ttk.Label(self.root, text="Remote Path:").grid(row=4, column=0, **padding)
        ttk.Entry(self.root, textvariable=self.remote_path).grid(row=4, column=1, **padding)

        ttk.Checkbutton(self.root, text="Recursive (folder)", variable=self.recursive).grid(row=5, column=1, sticky='w', **padding)

        file_entry = ttk.Entry(self.root, textvariable=self.file_path, width=50)
        file_entry.grid(row=6, column=0, columnspan=2, **padding)
        file_entry.drop_target_register(DND_FILES)
        file_entry.dnd_bind('<<Drop>>', self.on_file_drop)

        ttk.Button(self.root, text="Browse", command=self.browse_file).grid(row=6, column=2, **padding)
        ttk.Button(self.root, text="Start Transfer", command=self.start_transfer).grid(row=7, column=1, **padding)

    def on_file_drop(self, event):
        path = event.data.strip('{}')  # Clean path with spaces
        self.file_path.set(path)

    def browse_file(self):
        if self.recursive.get():
            selected = filedialog.askdirectory()
        else:
            selected = filedialog.askopenfilename()
        if selected:
            self.file_path.set(selected)

    def prompt_password(self):
        popup = tk.Toplevel(self.root)
        popup.title("Enter SSH Password")
        tk.Label(popup, text="Password:").pack(padx=10, pady=5)
        password_var = tk.StringVar()
        entry = tk.Entry(popup, textvariable=password_var, show="*")
        entry.pack(padx=10, pady=5)
        entry.focus()

        def submit():
            self.password = password_var.get()
            popup.destroy()

        tk.Button(popup, text="Submit", command=submit).pack(pady=10)
        popup.grab_set()

    def start_transfer(self):
        if not all([self.hostname.get(), self.username.get(), self.file_path.get(), self.remote_path.get()]):
            messagebox.showerror("Error", "All fields must be completed.")
            return
        if self.password is None:
            messagebox.showerror("Error", "Password not entered.")
            return

        try:
            ssh = create_ssh_client(
                self.hostname.get(),
                int(self.port.get()),
                self.username.get(),
                self.password
            )
            scp_upload(ssh, self.file_path.get(), self.remote_path.get(), self.recursive.get())
            messagebox.showinfo("Success", "File transferred successfully.")
            ssh.close()
            save_session({
                'host': self.hostname.get(),
                'port': self.port.get(),
                'user': self.username.get()
            })
        except Exception as e:
            messagebox.showerror("Transfer Failed", str(e))

    def load_session(self):
        session = load_session()
        if session:
            self.hostname.set(session.get('host', ''))
            self.port.set(session.get('port', '22'))
            self.username.set(session.get('user', ''))

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = SCPGuiApp(root)
    root.mainloop()
