import os
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, NamedTuple, Optional, Tuple
from datetime import datetime

# Style constants
BACKGROUND_COLOR = "#1E1E1E"
FOREGROUND_COLOR = "#E0E0E0"
ACCENT_COLOR = "#0288D1"
ACCENT_COLOR_ACTIVE = "#03A9F4"
CARD_COLOR = "#2C2C2C"
PADDING = 10
FONT_DEFAULT = ("Helvetica", 10)
FONT_BOLD = ("Helvetica", 10, "bold")
BUTTON_FONT = ("Helvetica", 9)
BUTTON_PADDING = 3

class FileInfo(NamedTuple):
    """Represents file metadata for integrity checking.
    
    Attributes:
        filename (str): Name of the file.
        extension (str): File extension.
        hash (str): Hash value of the file.
    """
    filename: str
    extension: str
    hash: str

class IntegrityCheckerGUI:
    """GUI application for checking file integrity against a reference hash file."""
    
    def __init__(self, root):
        """Initialize the IntegrityCheckerGUI.

        Args:
            root (tk.Tk): The root Tkinter window.
        """
        self.root = root
        self.root.title("Version File Integrity Check")
        self.root.geometry("640x570")
        self.root.resizable(False, False)
        self.root.configure(bg=BACKGROUND_COLOR)
        
        # Set window icon
        try:
            icon_path = os.path.join(os.path.dirname(__file__), "icon", "logo_app.png")
            self.root.iconphoto(True, tk.PhotoImage(file=icon_path))
        except Exception as e:
            print(f"Warning: Could not load icon: {e}")
        
        self.log_messages = []
        self.log_file_path = None
        
        # Configure style
        style = ttk.Style()
        style.theme_use('default')
        
        style.configure("TFrame", background=BACKGROUND_COLOR)
        style.configure("TLabel", background=BACKGROUND_COLOR, foreground=FOREGROUND_COLOR, font=FONT_DEFAULT)
        style.configure("Success.TLabel", foreground="#4CAF50", background=BACKGROUND_COLOR, font=FONT_BOLD)
        style.configure("Error.TLabel", foreground="#F44336", background=BACKGROUND_COLOR, font=FONT_BOLD)
        
        style.configure("TButton", 
                       background=ACCENT_COLOR,
                       foreground=FOREGROUND_COLOR,
                       font=BUTTON_FONT,
                       padding=BUTTON_PADDING)
        style.map("TButton",
                 background=[('active', ACCENT_COLOR_ACTIVE)],
                 foreground=[('active', FOREGROUND_COLOR)])
        
        style.configure("Treeview",
                       background=CARD_COLOR,
                       foreground=FOREGROUND_COLOR,
                       fieldbackground=CARD_COLOR,
                       font=FONT_DEFAULT)
        style.configure("Treeview.Heading",
                       background=ACCENT_COLOR,
                       foreground=FOREGROUND_COLOR,
                       font=FONT_BOLD)
        style.map("Treeview",
                 background=[('selected', ACCENT_COLOR)],
                 foreground=[('selected', FOREGROUND_COLOR)])
        
        style.configure("TEntry",
                       fieldbackground=CARD_COLOR,
                       foreground=FOREGROUND_COLOR,
                       font=FONT_DEFAULT)
        
        self.create_widgets()
        self.create_debug_console()
        
    def create_debug_console(self):
        """Set up the debug console text widget."""
        self.debug_text = tk.Text(self.root, 
                                height=5, 
                                width=70, 
                                state='disabled',
                                bg=CARD_COLOR,
                                fg=FOREGROUND_COLOR,
                                font=FONT_DEFAULT,
                                borderwidth=0,
                                highlightthickness=0)
        self.debug_text.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=PADDING)
        self.debug_text.configure(wrap=tk.WORD)
        
        self.debug_text.tag_configure("link", foreground=ACCENT_COLOR, underline=1)
        self.debug_text.tag_bind("link", "<Button-1>", self.open_log_file)
        self.debug_text.tag_bind("link", "<Enter>", lambda e: self.debug_text.config(cursor="hand2"))
        self.debug_text.tag_bind("link", "<Leave>", lambda e: self.debug_text.config(cursor=""))
        
        self.debug_print("\n---- Log ----")    

    def debug_print(self, message, link=False):
        """Display a message in the debug console.

        Args:
            message (str): The message to display.
            link (bool, optional): If True, display as a clickable link. Defaults to False.
        """
        self.debug_text.configure(state='normal')
        if link:
            self.debug_text.insert(tk.END, f"{message}\n", "link")
        else:
            self.debug_text.insert(tk.END, f"{message}\n")
        self.debug_text.see(tk.END)
        self.debug_text.configure(state='disabled')
        self.log_messages.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        self.root.update()
    
    def open_log_file(self, event):
        """Open the saved log file in the default system application.

        Args:
            event: The event triggering the action (mouse click).
        """
        if self.log_file_path and os.path.exists(self.log_file_path):
            try:
                os.startfile(self.log_file_path)  # Windows
            except AttributeError:
                try:
                    os.system(f"open {self.log_file_path}")  # macOS
                except:
                    try:
                        os.system(f"xdg-open {self.log_file_path}")  # Linux
                    except:
                        self.debug_print("Error: Could not open log file")

    def save_log(self, directory):
        """Save the log messages to a file in the specified directory.

        Args:
            directory (str): The directory where the log file will be saved.
        """
        try:
            self.log_file_path = os.path.join(directory, "vic_log.txt")
            with open(self.log_file_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(self.log_messages))
            self.debug_print(f"Log saved to {self.log_file_path}", link=True)
        except Exception as e:
            self.debug_print(f"Error saving log: {e}")
            messagebox.showerror("Error", f"Failed to save log file: {e}")
        
    def create_widgets(self):
        """Create and arrange the main GUI widgets."""
        main_frame = ttk.Frame(self.root, padding=PADDING)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Directory to check:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.dir_entry = ttk.Entry(main_frame, width=60)
        self.dir_entry.grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_directory).grid(row=0, column=2)
        
        self.check_button = ttk.Button(main_frame, text="Check Integrity", command=self.check_integrity)
        self.check_button.grid(row=1, column=0, columnspan=3, pady=10)
        
        self.create_treeview(main_frame)
        
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var)
        self.status_label.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=5)
        
    def create_treeview(self, parent):
        """Create and configure the Treeview widget for displaying file check results.

        Args:
            parent: The parent widget to contain the Treeview.
        """
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.tree = ttk.Treeview(tree_frame, columns=("Extension", "Hash", "Status"), height=15)
        
        self.tree.heading("#0", text="Filename")
        self.tree.heading("Extension", text="Extension")
        self.tree.heading("Hash", text="Current Hash")
        self.tree.heading("Status", text="Status")
        
        self.tree.column("#0", width=250)
        self.tree.column("Extension", width=100)
        self.tree.column("Hash", width=150)
        self.tree.column("Status", width=100)
        
        scrollbar = ttk.Scrollbar(tree_frame, 
                                orient=tk.VERTICAL, 
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.tree.tag_configure("success", foreground="#4CAF50")
        self.tree.tag_configure("error", foreground="#F44336")
        
    def browse_directory(self):
        """Open a directory selection dialog and update the entry field."""
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)
            self.debug_print(f"Selected directory: {directory}")
            
    def calculate_file_hash(self, filepath: str) -> Optional[str]:
        """Calculate the SHA-1 hash of a file.

        Args:
            filepath (str): Path to the file.

        Returns:
            Optional[str]: The first 16 characters of the SHA-1 hash, or None if an error occurs.
        """
        try:
            with open(filepath, 'rb') as f:
                sha1 = hashlib.sha1()
                for chunk in iter(lambda: f.read(4096), b''):
                    sha1.update(chunk)
                return sha1.hexdigest()[:16]
        except Exception as e:
            self.debug_print(f"Error calculating hash for {filepath}: {e}")
            return None
            
    def parse_reference_data(self, filepath: str) -> Tuple[Dict[str, FileInfo], str]:
        """Parse reference hash data from a file.

        Args:
            filepath (str): Path to the reference file.

        Returns:
            Tuple[Dict[str, FileInfo], str]: A dictionary of file info and the final message.
        """
        reference_data = {}
        final_message = ""
        try:
            self.debug_print(f"Reading reference file: {filepath}")
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                self.debug_print(f"File content length: {len(''.join(lines))} bytes")
                
                for line in lines[:-1]:
                    line = line.strip()
                    if not line:
                        continue
                        
                    parts = [part for part in line.split() if part]
                    
                    if len(parts) >= 2:
                        filename = parts[0]
                        hash_value = parts[1]
                        extension = os.path.splitext(filename)[1] if '.' in filename else ''
                        
                        reference_data[filename] = FileInfo(
                            filename=filename,
                            extension=extension,
                            hash=hash_value
                        )
                        self.debug_print(f"Parsed: {filename} - {hash_value}")
                    else:
                        self.debug_print(f"Skipping invalid line: {line}")
                
                if lines:
                    final_message = lines[-1].strip()
                    self.debug_print(f"Final message: {final_message}")
                        
            self.debug_print(f"Parsed {len(reference_data)} files from reference data")
            
        except Exception as e:
            self.debug_print(f"Error reading reference file: {e}")
            messagebox.showerror("Error", f"Error reading reference file: {e}")
            return {}, ""
            
        return reference_data, final_message
        
    def check_integrity(self):
        """Perform the file integrity check against reference data."""
        try:
            self.log_messages = []
            self.debug_print("\n--- Starting integrity check ---")
            self.check_button.configure(state='disabled')
            
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            directory = self.dir_entry.get()
            
            if not directory:
                self.debug_print("Error: Missing directory")
                messagebox.showwarning("Warning", "Select a directory to check")
                return
                
            if not os.path.exists(directory):
                self.debug_print("Error: Directory does not exist")
                messagebox.showerror("Error", "Selected directory does not exist")
                return
                
            ref_file = os.path.join(directory, "file_hashes.txt")
            if not os.path.exists(ref_file):
                self.debug_print("Error: file_hashes.txt not found in selected directory")
                messagebox.showerror("Error", "file_hashes.txt not found in selected directory")
                return
                
            reference_data, final_message = self.parse_reference_data(ref_file)
            if not reference_data:
                self.debug_print("Error: No valid reference data found")
                return
                
            all_ok = True
            total_files = len(reference_data)
            checked_files = 0
            
            self.debug_print(f"Starting to check {total_files} files")
            
            for filename, info in sorted(reference_data.items()):
                # Skip file_hashes.txt and vic_log.txt
                if filename in ("file_hashes.txt", "vic_log.txt"):
                    self.debug_print(f"\nSkipping hash check for {filename}")
                    continue
                    
                filepath = os.path.join(directory, filename)
                checked_files += 1
                
                self.debug_print(f"\nChecking file {checked_files}/{total_files}: {filename}")
                
                if not os.path.exists(filepath):
                    self.debug_print(f"File missing: {filepath}")
                    self.tree.insert("", tk.END, text=filename, values=(
                        info.extension, "---", "MISSING"
                    ), tags=("error",))
                    all_ok = False
                    continue
                    
                actual_hash = self.calculate_file_hash(filepath)
                
                self.debug_print(f"Expected hash: {info.hash}")
                self.debug_print(f"Actual hash: {actual_hash}")
                
                status = "OK"
                tags = ("success",)
                
                if actual_hash != info.hash:
                    status = "HASH MISMATCH"
                    tags = ("error",)
                    all_ok = False
                    
                self.tree.insert("", tk.END, text=filename, values=(
                    info.extension, actual_hash, status
                ), tags=tags)
                
                self.status_var.set(f"Checking files... {checked_files}/{total_files}")
                self.root.update()
                
            timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            status_text = f"Check completed at {timestamp}. Status: {'OK' if all_ok else 'FAILED'}"
            if all_ok and final_message:
                status_text += f"\n Version: {final_message}"
            self.status_var.set(status_text)
            self.status_label.configure(style="Success.TLabel" if all_ok else "Error.TLabel")
            
            if all_ok:
                message = "All files passed integrity check!"
                if final_message:
                    message += f"\n\n Version: {final_message}"
                messagebox.showinfo("Success", message)
            else:
                messagebox.showwarning("Warning", "Some files failed integrity check. Check the results for details.")
                
        except Exception as e:
            self.debug_print(f"Unexpected error: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            
        finally:
            self.check_button.configure(state='normal')
            if self.dir_entry.get():
                self.save_log(self.dir_entry.get())

def main():
    """Entry point for the Integrity Checker application."""
    root = tk.Tk()
    app = IntegrityCheckerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

 
