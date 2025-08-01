#!/usr/bin/env python3
"""
Unified Encrypted Chat Application
A single application that can run as either server or client with GUI selection.
Supports bidirectional encrypted messaging using Fernet symmetric encryption.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import socket
import threading
import json
import datetime
import os
from cryptography.fernet import Fernet

class EncryptedChatApp:
    def __init__(self):
        # Connection configuration
        self.default_host = '192.168.101.12'  # Change this to your preferred default IP
        self.default_port = 12345
        
        # Network objects
        self.server_socket = None
        self.client_socket = None
        self.peer_socket = None  # The socket we communicate through
        self.peer_address = None
        
        # Application state
        self.mode = None  # 'server' or 'client'
        self.connected = False
        self.is_server = False
        
        # Encryption setup - SHARED KEY
        # In production, you'd want to use key exchange protocols
        # For testing purposes, we'll use a hardcoded key that both ends know
        self.encryption_key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='  # Base64 encoded key
        self.cipher = Fernet(self.encryption_key)
        
        # Chat history file
        self.history_file = 'chat_history.txt'
        
        # Username
        self.username = "User"
        
        # GUI setup
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI interface"""
        self.root = tk.Tk()
        self.root.title("Encrypted Chat Application")
        self.root.geometry("650x600")
        
        # Mode selection frame (initially visible)
        self.mode_frame = tk.Frame(self.root, bg="#f0f0f0", relief="ridge", bd=2)
        self.mode_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(self.mode_frame, text="🔐 Encrypted Chat Application", 
                font=("Arial", 16, "bold"), bg="#f0f0f0", fg="#2c3e50").pack(pady=10)
        
        tk.Label(self.mode_frame, text="Choose your mode:", 
                font=("Arial", 12), bg="#f0f0f0").pack(pady=5)
        
        mode_buttons_frame = tk.Frame(self.mode_frame, bg="#f0f0f0")
        mode_buttons_frame.pack(pady=10)
        
        self.server_btn = tk.Button(mode_buttons_frame, text="🖥️ Run as Server\n(Wait for connections)", 
                                   command=self.setup_server_mode,
                                   bg="#3498db", fg="white", font=("Arial", 11, "bold"),
                                   width=20, height=3)
        self.server_btn.pack(side=tk.LEFT, padx=10)
        
        self.client_btn = tk.Button(mode_buttons_frame, text="💻 Run as Client\n(Connect to server)", 
                                   command=self.setup_client_mode,
                                   bg="#e74c3c", fg="white", font=("Arial", 11, "bold"),
                                   width=20, height=3)
        self.client_btn.pack(side=tk.LEFT, padx=10)
        
        # Connection configuration frame (initially hidden)
        self.config_frame = tk.Frame(self.root)
        
        # Server configuration
        self.server_config_frame = tk.Frame(self.config_frame)
        
        tk.Label(self.server_config_frame, text="Server Configuration", 
                font=("Arial", 12, "bold")).pack(pady=5)
        
        server_settings_frame = tk.Frame(self.server_config_frame)
        server_settings_frame.pack(pady=5)
        
        tk.Label(server_settings_frame, text="Listen Port:").pack(side=tk.LEFT)
        self.server_port_entry = tk.Entry(server_settings_frame, width=8)
        self.server_port_entry.pack(side=tk.LEFT, padx=5)
        self.server_port_entry.insert(0, str(self.default_port))
        
        self.start_server_btn = tk.Button(server_settings_frame, text="Start Server", 
                                        command=self.start_server,
                                        bg="#27ae60", fg="white", font=("Arial", 10, "bold"))
        self.start_server_btn.pack(side=tk.LEFT, padx=10)
        
        # Client configuration
        self.client_config_frame = tk.Frame(self.config_frame)
        
        tk.Label(self.client_config_frame, text="Client Configuration", 
                font=("Arial", 12, "bold")).pack(pady=5)
        
        client_settings_frame = tk.Frame(self.client_config_frame)
        client_settings_frame.pack(pady=5)
        
        tk.Label(client_settings_frame, text="Server IP:").pack(side=tk.LEFT)
        self.client_host_entry = tk.Entry(client_settings_frame, width=15)
        self.client_host_entry.pack(side=tk.LEFT, padx=5)
        self.client_host_entry.insert(0, self.default_host)
        
        tk.Label(client_settings_frame, text="Port:").pack(side=tk.LEFT, padx=(10,0))
        self.client_port_entry = tk.Entry(client_settings_frame, width=8)
        self.client_port_entry.pack(side=tk.LEFT, padx=5)
        self.client_port_entry.insert(0, str(self.default_port))
        
        self.connect_btn = tk.Button(client_settings_frame, text="Connect", 
                                   command=self.connect_to_server,
                                   bg="#3498db", fg="white", font=("Arial", 10, "bold"))
        self.connect_btn.pack(side=tk.LEFT, padx=10)
        
        # Username configuration
        username_frame = tk.Frame(self.config_frame)
        username_frame.pack(pady=10)
        
        tk.Label(username_frame, text="Username:").pack(side=tk.LEFT)
        self.username_entry = tk.Entry(username_frame, width=20)
        self.username_entry.pack(side=tk.LEFT, padx=5)
        self.username_entry.insert(0, "User")
        
        set_username_btn = tk.Button(username_frame, text="Set Username", 
                                   command=self.set_username)
        set_username_btn.pack(side=tk.LEFT, padx=5)
        
        # Back button
        back_btn = tk.Button(self.config_frame, text="← Back to Mode Selection", 
                           command=self.show_mode_selection,
                           bg="#95a5a6", fg="white")
        back_btn.pack(pady=10)
        
        # Main chat interface (initially hidden)
        self.chat_frame = tk.Frame(self.root)
        
        # Connection status
        self.status_label = tk.Label(self.chat_frame, text="Not connected", 
                                   fg="red", font=("Arial", 10, "bold"))
        self.status_label.pack(pady=5)
        
        # Chat history area
        self.chat_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, 
                                                 width=70, height=20, state=tk.DISABLED)
        self.chat_area.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        # Message input frame
        input_frame = tk.Frame(self.chat_frame)
        input_frame.pack(pady=5, padx=10, fill=tk.X)
        
        self.message_entry = tk.Entry(input_frame, font=("Arial", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', self.send_message)
        
        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message,
                                   bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.send_button.pack(side=tk.RIGHT)
        
        # Control buttons
        control_frame = tk.Frame(self.chat_frame)
        control_frame.pack(pady=5)
        
        load_history_btn = tk.Button(control_frame, text="Load Chat History", 
                                   command=self.load_chat_history)
        load_history_btn.pack(side=tk.LEFT, padx=5)
        
        clear_chat_btn = tk.Button(control_frame, text="Clear Chat", 
                                 command=self.clear_chat)
        clear_chat_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = tk.Button(control_frame, text="Disconnect", 
                                      command=self.disconnect,
                                      bg="#f44336", fg="white")
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        restart_btn = tk.Button(control_frame, text="Restart App", 
                              command=self.restart_app,
                              bg="#ff9800", fg="white")
        restart_btn.pack(side=tk.LEFT, padx=5)
        
        # Encryption info
        encryption_info = tk.Label(self.chat_frame, 
                                 text=f"🔐 Encryption: Fernet (Key: {self.encryption_key[:20].decode()}...)",
                                 fg="blue", font=("Arial", 8))
        encryption_info.pack(pady=2)
        
        # Initially disable message input
        self.message_entry.config(state=tk.DISABLED)
        self.send_button.config(state=tk.DISABLED)
        
        # Load existing chat history
        self.load_chat_history()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Show mode selection initially
        self.show_mode_selection()
    
    def show_mode_selection(self):
        """Show the mode selection screen"""
        self.config_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.mode_frame.pack(fill=tk.X, padx=10, pady=10)
        self.root.title("Encrypted Chat Application - Mode Selection")
    
    def setup_server_mode(self):
        """Setup server mode configuration"""
        self.mode = 'server'
        self.is_server = True
        self.mode_frame.pack_forget()
        self.server_config_frame.pack(pady=10)
        self.config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.root.title("Encrypted Chat Application - Server Mode")
    
    def setup_client_mode(self):
        """Setup client mode configuration"""
        self.mode = 'client'
        self.is_server = False
        self.mode_frame.pack_forget()
        self.client_config_frame.pack(pady=10)
        self.config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.root.title("Encrypted Chat Application - Client Mode")
    
    def set_username(self):
        """Set the username from the entry field"""
        new_username = self.username_entry.get().strip()
        if new_username:
            self.username = new_username
            if hasattr(self, 'chat_area'):
                self.display_message(f"Username set to: {self.username}", "SYSTEM")
    
    def start_server(self):
        """Start the server"""
        try:
            port = int(self.server_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number!")
            return
        
        def server_thread():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', port))
                self.server_socket.listen(1)
                
                # Switch to chat interface
                self.root.after(0, self.show_chat_interface)
                self.root.after(0, lambda: self.update_status(f"Server listening on port {port}. Waiting for client...", "orange"))
                self.root.after(0, lambda: self.display_message(f"Server started on port {port}. Waiting for client...", "SYSTEM"))
                
                # Accept client connection
                self.peer_socket, self.peer_address = self.server_socket.accept()
                
                # Update GUI
                self.connected = True
                self.root.after(0, lambda: self.update_status(f"Client connected: {self.peer_address[0]}", "green"))
                self.root.after(0, lambda: self.display_message(f"Client connected from {self.peer_address[0]}", "SYSTEM"))
                
                # Enable message input
                self.root.after(0, self.enable_messaging)
                
                # Start receiving messages
                self.receive_messages()
                
            except Exception as e:
                self.root.after(0, lambda: self.update_status(f"Server error: {str(e)}", "red"))
                self.root.after(0, lambda: self.display_message(f"Server error: {str(e)}", "ERROR"))
        
        threading.Thread(target=server_thread, daemon=True).start()
    
    def connect_to_server(self):
        """Connect to the server as client"""
        host = self.client_host_entry.get().strip()
        try:
            port = int(self.client_port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number!")
            return
        
        def connect_thread():
            try:
                self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.peer_socket.settimeout(10)  # 10 second timeout
                
                # Switch to chat interface and update status
                self.root.after(0, self.show_chat_interface)
                self.root.after(0, lambda: self.update_status("Connecting...", "orange"))
                
                # Connect to server
                self.peer_socket.connect((host, port))
                
                # Remove timeout after connection
                self.peer_socket.settimeout(None)
                
                # Update GUI
                self.connected = True
                self.root.after(0, lambda: self.update_status(f"Connected to {host}:{port}", "green"))
                self.root.after(0, lambda: self.display_message(f"Connected to server at {host}:{port}", "SYSTEM"))
                
                # Enable message input
                self.root.after(0, self.enable_messaging)
                
                # Start receiving messages
                self.receive_messages()
                
            except Exception as e:
                self.connected = False
                self.root.after(0, lambda: self.update_status(f"Connection failed: {str(e)}", "red"))
                self.root.after(0, lambda: self.display_message(f"Connection failed: {str(e)}", "ERROR"))
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def show_chat_interface(self):
        """Show the main chat interface"""
        self.config_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.root.title(f"Encrypted Chat Application - {self.mode.title()} Mode")
    
    def enable_messaging(self):
        """Enable message input controls"""
        self.message_entry.config(state=tk.NORMAL)
        self.send_button.config(state=tk.NORMAL)
        self.message_entry.focus_set()
    
    def receive_messages(self):
        """Receive messages from peer"""
        def receive_thread():
            try:
                while self.connected and self.peer_socket:
                    # Receive encrypted message
                    encrypted_data = self.peer_socket.recv(4096)
                    if not encrypted_data:
                        break
                    
                    try:
                        # Decrypt the message
                        decrypted_data = self.cipher.decrypt(encrypted_data)
                        message_data = json.loads(decrypted_data.decode())
                        
                        sender = message_data.get('sender', 'Peer')
                        message = message_data.get('message', '')
                        timestamp = message_data.get('timestamp', '')
                        
                        # Display in GUI
                        self.root.after(0, lambda: self.display_message(message, sender, timestamp))
                        
                        # Save to history
                        self.save_to_history(sender, message, timestamp)
                        
                    except Exception as decrypt_error:
                        self.root.after(0, lambda: self.display_message(f"Failed to decrypt message: {str(decrypt_error)}", "ERROR"))
                
            except Exception as e:
                if self.connected:  # Only show error if we were supposed to be connected
                    self.root.after(0, lambda: self.update_status("Disconnected from peer", "red"))
                    self.root.after(0, lambda: self.display_message("Disconnected from peer", "SYSTEM"))
                
                # Update connection state
                self.connected = False
                # Disable message input
                self.root.after(0, lambda: self.message_entry.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.send_button.config(state=tk.DISABLED))
        
        threading.Thread(target=receive_thread, daemon=True).start()
    
    def send_message(self, event=None):
        """Send message to peer"""
        message = self.message_entry.get().strip()
        if not message or not self.connected or not self.peer_socket:
            return
        
        try:
            # Create message data
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message_data = {
                'sender': self.username,
                'message': message,
                'timestamp': timestamp
            }
            
            # Encrypt the message
            json_data = json.dumps(message_data).encode()
            encrypted_data = self.cipher.encrypt(json_data)
            
            # Send encrypted message
            self.peer_socket.send(encrypted_data)
            
            # Display in our GUI
            self.display_message(message, "You", timestamp)
            
            # Save to history
            self.save_to_history(self.username, message, timestamp)
            
            # Clear input field
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            self.display_message(f"Failed to send message: {str(e)}", "ERROR")
    
    def disconnect(self):
        """Disconnect from peer"""
        if self.connected:
            try:
                self.connected = False
                if self.peer_socket:
                    self.peer_socket.close()
                    self.peer_socket = None
                if self.server_socket:
                    self.server_socket.close()
                    self.server_socket = None
                
                self.update_status("Disconnected", "red")
                self.display_message("Disconnected", "SYSTEM")
                
                # Disable message input
                self.message_entry.config(state=tk.DISABLED)
                self.send_button.config(state=tk.DISABLED)
                
            except Exception as e:
                self.display_message(f"Error disconnecting: {str(e)}", "ERROR")
    
    def restart_app(self):
        """Restart the application"""
        self.disconnect()
        self.show_mode_selection()
        self.connected = False
        self.mode = None
        self.is_server = False
    
    def display_message(self, message, sender, timestamp=None):
        """Display message in chat area"""
        self.chat_area.config(state=tk.NORMAL)
        
        if timestamp is None:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if sender == "SYSTEM":
            self.chat_area.insert(tk.END, f"[{timestamp}] 🔧 SYSTEM: {message}\n")
        elif sender == "ERROR":
            self.chat_area.insert(tk.END, f"[{timestamp}] ❌ ERROR: {message}\n")
        elif sender == "You":
            self.chat_area.insert(tk.END, f"[{timestamp}] You: {message}\n")
        else:
            self.chat_area.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
        
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)
    
    def save_to_history(self, sender, message, timestamp):
        """Save message to chat history file"""
        try:
            with open(self.history_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {sender}: {message}\n")
        except Exception as e:
            print(f"Failed to save to history: {e}")
    
    def load_chat_history(self):
        """Load chat history from file"""
        if os.path.exists(self.history_file):
            try:
                self.chat_area.config(state=tk.NORMAL)
                self.chat_area.delete(1.0, tk.END)
                
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history = f.read()
                    if history:
                        self.chat_area.insert(tk.END, "📜 Previous Chat History:\n")
                        self.chat_area.insert(tk.END, history)
                        self.chat_area.insert(tk.END, "\n" + "="*50 + "\n")
                
                self.chat_area.config(state=tk.DISABLED)
                self.chat_area.see(tk.END)
                
            except Exception as e:
                if hasattr(self, 'chat_area'):
                    self.display_message(f"Failed to load chat history: {str(e)}", "ERROR")
    
    def clear_chat(self):
        """Clear the chat area"""
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.delete(1.0, tk.END)
        self.chat_area.config(state=tk.DISABLED)
    
    def update_status(self, status, color):
        """Update status label"""
        self.status_label.config(text=status, fg=color)
    
    def on_closing(self):
        """Handle window closing"""
        self.disconnect()
        self.root.destroy()
    
    def run(self):
        """Start the GUI main loop"""
        self.root.mainloop()

if __name__ == "__main__":
    # Print important information
    print("🔐 Unified Encrypted Chat Application")
    print("=" * 40)
    print("This application can run as either server or client.")
    print("Encryption Key (Base64):", "ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg=")
    print("Both machines must use the SAME application file.")
    print("Choose your mode in the GUI: Server or Client")
    print("=" * 40)
    
    app = EncryptedChatApp()
    app.run()