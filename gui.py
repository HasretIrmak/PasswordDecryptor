import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from backend import (
    hash_password, password_cracker, generate_key, load_key,
    encrypt_wordlist, decrypt_wordlist
)

def encrypt_file():
    input_file = filedialog.askopenfilename(title="Select Wordlist File to Encrypt")
    if not input_file:
        return
    
    output_file = filedialog.asksaveasfilename(title="Save Encrypted File", defaultextension=".enc")
    if not output_file:
        return
    
    key = load_key()
    encrypt_wordlist(input_file, output_file, key)
    messagebox.showinfo("Success", "File successfully encrypted!")

def start_cracking():
    target_password = target_entry.get()
    algorithm = algorithm_var.get()
    if not target_password:
        messagebox.showwarning("Warning", "Please enter the target password!")
        return
    
    target_hash = hash_password(target_password, algorithm)
    wordlist_path = filedialog.askopenfilename(title="Select Encrypted Wordlist File")
    if not wordlist_path:
        messagebox.showwarning("Warning", "You did not select a wordlist file!")
        return
    
    try:
        wordlist = decrypt_wordlist(wordlist_path, load_key())
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt wordlist: {e}")
        return
    
    progress_var.set(0)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Target Hash: {target_hash}\nStarting password cracking...\n")
    
    total_words = len(wordlist)
    for index, word in enumerate(wordlist):
        progress_var.set((index + 1) / total_words * 100)
        app.update_idletasks()
        if hash_password(word, algorithm) == target_hash:
            result_text.insert(tk.END, f"Success! Password found: {word}\n")
            return
    
    result_text.insert(tk.END, "Failed! Password not found.\n")

# GUI Setup
app = tk.Tk()
app.title("Password Cracker")
app.geometry("500x500")

tk.Label(app, text="Target Password:", font=("Arial", 12)).pack(pady=5)
target_entry = tk.Entry(app, font=("Arial", 12), width=40)
target_entry.pack(pady=5)

tk.Label(app, text="Hash Algorithm:", font=("Arial", 12)).pack(pady=5)
algorithm_var = tk.StringVar(value="md5")
tk.OptionMenu(app, algorithm_var, "md5", "sha256").pack(pady=5)

tk.Button(app, text="Encrypt Wordlist", font=("Arial", 12), command=encrypt_file).pack(pady=5)

progress_var = tk.DoubleVar()
ttk.Progressbar(app, variable=progress_var, maximum=100).pack(pady=10, fill=tk.X)

tk.Button(app, text="Start Cracking Password", font=("Arial", 12), command=start_cracking).pack(pady=10)

result_text = scrolledtext.ScrolledText(app, font=("Arial", 10), width=60, height=10)
result_text.pack(pady=10)

tk.Button(app, text="Generate Key", font=("Arial", 12), command=lambda: generate_key()).pack(pady=5)

app.mainloop()
