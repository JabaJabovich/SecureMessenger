import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import logging
from auth import AuthManager
from models import User, Database, Message
from crypto import RSAECCEncryptor, PasswordHasher
import time
import json
import traceback

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class SecureMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Безопасный мессенджер")
        self.root.geometry("800x600")

        try:
            self.db = Database()
            self.auth = AuthManager(self.db)
            logging.info("Application initialized successfully")
        except Exception as e:
            logging.critical(f"Initialization failed: {str(e)}")
            messagebox.showerror("Ошибка", "Не удалось инициализировать приложение")
            self.root.destroy()
            return

        if not self.db.get_user("admin"):
            self._create_admin_user()

        self.current_user = None
        self.selected_user = None

        self._setup_ui()
        self.show_login_screen()

    def _setup_ui(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.container = ttk.Frame(self.root)
        self.container.grid(row=0, column=0, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

    def _create_admin_user(self):
        try:
            admin_password = "admin123"
            self.auth.register_user("admin", admin_password, roles=['admin', 'user'])
            logging.info("Default admin user created")
        except Exception as e:
            logging.error(f"Failed to create admin user: {str(e)}")

    def show_login_screen(self):
        self._clear_container()

        frame = ttk.Frame(self.container, padding=20)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Безопасный мессенджер", font=('Helvetica', 16, 'bold')).pack(pady=10)
        ttk.Label(frame, text="Логин").pack()

        self.login_username = ttk.Entry(frame)
        self.login_username.pack(pady=5)
        self.login_username.focus()

        ttk.Label(frame, text="Пароль").pack()
        self.login_password = ttk.Entry(frame, show="*")
        self.login_password.pack(pady=5)

        ttk.Button(frame, text="Войти", command=self._handle_login).pack(pady=10)
        ttk.Button(frame, text="Регистрация", command=self.show_register_screen).pack()

        self.login_error = ttk.Label(frame, text="", foreground="red")
        self.login_error.pack(pady=5)

        self.root.bind('<Return>', lambda e: self._handle_login())

    def show_register_screen(self):
        self._clear_container()

        frame = ttk.Frame(self.container, padding=20)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Регистрация", font=('Helvetica', 16, 'bold')).pack(pady=10)

        ttk.Label(frame, text="Имя пользователя (мин. 3 символа)").pack()
        self.reg_username = ttk.Entry(frame)
        self.reg_username.pack(pady=5)
        self.reg_username.focus()

        ttk.Label(frame, text="Пароль (мин. 6 символов)").pack()
        self.reg_password = ttk.Entry(frame, show="*")
        self.reg_password.pack(pady=5)

        ttk.Label(frame, text="Подтверждение пароля").pack()
        self.reg_confirm = ttk.Entry(frame, show="*")
        self.reg_confirm.pack(pady=5)

        ttk.Button(frame, text="Зарегистрироваться", command=self._handle_register).pack(pady=10)
        ttk.Button(frame, text="Назад к входу", command=self.show_login_screen).pack()

        self.reg_error = ttk.Label(frame, text="", foreground="red")
        self.reg_error.pack(pady=5)

    def show_main_screen(self):
        self._clear_container()

        main_frame = ttk.Frame(self.container)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        user_frame = ttk.LabelFrame(main_frame, text="Пользователи", padding=10, width=150)
        user_frame.grid(row=0, column=0, sticky="ns")
        user_frame.grid_propagate(False)

        self.user_listbox = tk.Listbox(user_frame)
        self.user_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self._update_user_list()

        self.user_listbox.bind('<<ListboxSelect>>', self._on_user_select)

        chat_frame = ttk.Frame(main_frame)
        chat_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        chat_frame.grid_rowconfigure(1, weight=1)
        chat_frame.grid_columnconfigure(0, weight=1)

        self.chat_header = ttk.Label(chat_frame, text="Выберите пользователя для чата", font=('Helvetica', 12))
        self.chat_header.grid(row=0, column=0, sticky="ew", pady=5)

        self.message_text = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            state='disabled',
            font=('Helvetica', 10)
        )
        self.message_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        input_frame = ttk.Frame(chat_frame)
        input_frame.grid(row=2, column=0, sticky="ew", pady=5)

        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.message_entry.bind('<Return>', lambda e: self._send_message())

        ttk.Button(input_frame, text="Отправить", command=self._send_message).pack(side="right", padx=5)

        status_frame = ttk.Frame(chat_frame)
        status_frame.grid(row=3, column=0, sticky="ew")

        ttk.Label(status_frame, text=f"Вход выполнен: {self.auth.get_current_user().username}").pack(side="left")

        if self.auth.has_permission('admin'):
            ttk.Button(
                status_frame,
                text="Панель администратора",
                command=self.show_admin_panel
            ).pack(side="left", padx=10)

        ttk.Button(status_frame, text="Выйти", command=self._logout).pack(side="right")

    def show_admin_panel(self):
        self._clear_container()

        main_frame = ttk.Frame(self.container)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=10)

        ttk.Label(
            header_frame,
            text="Панель администратора",
            font=('Helvetica', 16, 'bold')
        ).pack(side="left", padx=20)

        ttk.Button(
            header_frame,
            text="Назад к чату",
            command=self.show_main_screen
        ).pack(side="right", padx=20)

        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=1, column=0, sticky="nsew")
        content_frame.grid_rowconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)

        user_frame = ttk.LabelFrame(content_frame, text="Управление пользователями", padding=10)
        user_frame.grid(row=0, column=0, sticky="ns", padx=5, pady=5)

        self.admin_user_list = tk.Listbox(user_frame, height=15, width=25)
        self.admin_user_list.pack(fill="both", expand=True, padx=5, pady=5)
        self._update_admin_user_list()

        self.user_info = scrolledtext.ScrolledText(
            user_frame,
            height=8,
            width=30,
            state='disabled'
        )
        self.user_info.pack(fill="x", padx=5, pady=5)

        role_frame = ttk.LabelFrame(user_frame, text="Роли", padding=10)
        role_frame.pack(fill="x", padx=5, pady=5)

        self.role_vars = {
            'admin': tk.IntVar(),
            'user': tk.IntVar()
        }

        ttk.Checkbutton(
            role_frame,
            text="Администратор",
            variable=self.role_vars['admin'],
            command=lambda: self._update_roles('admin')
        ).pack(anchor="w")

        ttk.Checkbutton(
            role_frame,
            text="Пользователь",
            variable=self.role_vars['user'],
            command=lambda: self._update_roles('user')
        ).pack(anchor="w")

        ttk.Button(
            user_frame,
            text="Удалить пользователя",
            command=self._delete_user
        ).pack(pady=5)

        messages_frame = ttk.LabelFrame(content_frame, text="Все сообщения", padding=10)
        messages_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        messages_frame.grid_rowconfigure(0, weight=1)
        messages_frame.grid_columnconfigure(0, weight=1)

        self.all_messages = scrolledtext.ScrolledText(
            messages_frame,
            wrap=tk.WORD,
            state='disabled'
        )
        self.all_messages.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        ttk.Button(
            messages_frame,
            text="Обновить",
            command=self._update_all_messages
        ).grid(row=1, column=0, pady=5)

        self.admin_user_list.bind('<<ListboxSelect>>', self._on_admin_user_select)
        self._update_all_messages()

    def _clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def _handle_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()

        if not username or not password:
            self.login_error.config(text="Требуется имя пользователя и пароль")
            return

        try:
            if self.auth.login(username, password):
                self.current_user = self.auth.get_current_user()
                self.show_main_screen()
            else:
                self.login_error.config(text="Неверное имя пользователя или пароль")
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            self.login_error.config(text="Ошибка входа")

    def _handle_register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get().strip()
        confirm = self.reg_confirm.get().strip()

        errors = []
        if len(username) < 3:
            errors.append("Имя пользователя должно быть не менее 3 символов")
        if len(password) < 6:
            errors.append("Пароль должен быть не менее 6 символов")
        if password != confirm:
            errors.append("Пароли не совпадают")

        if errors:
            self.reg_error.config(text="\n".join(errors))
            return

        try:
            self.auth.register_user(username, password)
            messagebox.showinfo("Успех", "Регистрация прошла успешно!")
            self.show_login_screen()
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            self.reg_error.config(text=str(e))

    def _logout(self):
        self.auth.logout()
        self.current_user = None
        self.selected_user = None
        self.show_login_screen()

    def _update_user_list(self):
        self.user_listbox.delete(0, tk.END)
        users = self.db.get_all_users()
        current_user = self.auth.get_current_user().username

        for user in users:
            if user.username != current_user:
                self.user_listbox.insert(tk.END, user.username)

    def _on_user_select(self, event):
        try:
            selection = self.user_listbox.curselection()
            if not selection:
                return

            self.selected_user = self.user_listbox.get(selection[0])
            self.chat_header.config(text=f"Чат с {self.selected_user}")
            self._update_message_history()
        except Exception as e:
            logging.error(f"User selection error: {str(e)}")

    def _update_message_history(self):
        encryptor = RSAECCEncryptor()
        if not self.selected_user:
            return

        self.message_text.config(state='normal')
        self.message_text.delete(1.0, tk.END)

        current_user = self.auth.get_current_user().username
        messages = self.db.get_messages(current_user)

        for msg in messages:
            if msg.sender == self.selected_user or msg.recipient == self.selected_user:
                try:

                    sender = self.db.get_user(msg.sender)
                    recipient = self.db.get_user(msg.recipient)


                    if msg.sender == current_user:

                        private_key = json.loads(recipient.private_key)
                    else:

                        private_key = json.loads(self.auth.get_current_user().private_key)

                    decrypted = encryptor.decrypt_message(
                        json.loads(msg.encrypted_data),
                        private_key
                    )

                    timestamp = time.strftime('%H:%M:%S', time.localtime(msg.timestamp))
                    prefix = f"[{timestamp}] {msg.sender}: "
                    self.message_text.insert(tk.END, prefix)

                    if msg.sender == current_user:
                        self.message_text.insert(tk.END, decrypted + '\n', 'sent')
                    else:
                        self.message_text.insert(tk.END, decrypted + '\n', 'received')
                except Exception as e:
                    logging.error(f"Ошибка расшифровки: {str(e)}")
                    self.message_text.insert(tk.END, f"[ОШИБКА] Не удалось расшифровать сообщение\n", 'error')

        self.message_text.tag_config('sent', foreground='blue')
        self.message_text.tag_config('received', foreground='green')
        self.message_text.tag_config('error', foreground='red')

        self.message_text.config(state='disabled')
        self.message_text.yview(tk.END)

    def _send_message(self):
        if not self.selected_user:
            messagebox.showerror("Ошибка", "Сначала выберите пользователя!")
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            current_user = self.auth.get_current_user()
            recipient = self.db.get_user(self.selected_user)

            if not recipient:
                messagebox.showerror("Ошибка", "Получатель не найден!")
                return

            encryptor = RSAECCEncryptor()


            current_user_public_key = json.loads(current_user.public_key)

            encrypted = encryptor.encrypt_message(
                message,
                json.loads(recipient.public_key),
                json.loads(current_user.private_key),
                current_user_public_key
            )

            msg = Message(
                sender=current_user.username,
                recipient=recipient.username,
                encrypted_data=json.dumps(encrypted),
                timestamp=time.time()
            )
            self.db.save_message(msg)

            self.message_entry.delete(0, tk.END)
            self._update_message_history()

        except Exception as e:
            logging.error(f"Message send error: {str(e)}\n{traceback.format_exc()}")
            messagebox.showerror("Ошибка", f"Не удалось отправить сообщение: {str(e)}")

    def _update_admin_user_list(self):
        self.admin_user_list.delete(0, tk.END)
        users = self.db.get_all_users()

        for user in users:
            self.admin_user_list.insert(tk.END, user.username)

    def _on_admin_user_select(self, event):
        try:
            selection = self.admin_user_list.curselection()
            if not selection:
                return

            username = self.admin_user_list.get(selection[0])
            user = self.db.get_user(username)

            if not user:
                return

            self.user_info.config(state='normal')
            self.user_info.delete(1.0, tk.END)

            info = (
                f"Имя: {user.username}\n"
                f"Роли: {', '.join(user.roles)}\n"
                f"Зарегистрирован: {self._get_user_registration_time(username)}"
            )
            self.user_info.insert(tk.END, info)
            self.user_info.config(state='disabled')

            self.role_vars['admin'].set(1 if 'admin' in user.roles else 0)
            self.role_vars['user'].set(1 if 'user' in user.roles else 0)

        except Exception as e:
            logging.error(f"Admin user select error: {str(e)}")

    def _get_user_registration_time(self, username):
        try:
            messages = self.db.get_all_messages()
            for msg in messages:
                if msg.sender == username:
                    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(msg.timestamp))
            return "неизвестно"
        except:
            return "неизвестно"

    def _update_roles(self, role):
        try:
            selection = self.admin_user_list.curselection()
            if not selection:
                return

            username = self.admin_user_list.get(selection[0])
            user = self.db.get_user(username)

            if not user:
                return

            new_roles = []
            if self.role_vars['admin'].get() == 1:
                new_roles.append('admin')
            if self.role_vars['user'].get() == 1:
                new_roles.append('user')

            self.db.update_user_roles(username, new_roles)
            logging.info(f"Updated roles for {username}: {new_roles}")
            self._on_admin_user_select(None)

        except Exception as e:
            logging.error(f"Role update error: {str(e)}")
            messagebox.showerror("Ошибка", "Не удалось обновить роли")

    def _delete_user(self):
        try:
            selection = self.admin_user_list.curselection()
            if not selection:
                return

            username = self.admin_user_list.get(selection[0])

            if username == self.auth.get_current_user().username:
                messagebox.showerror("Ошибка", "Вы не можете удалить себя!")
                return

            if messagebox.askyesno(
                    "Подтверждение",
                    f"Удалить пользователя {username}? Все его сообщения также будут удалены.",
                    icon='warning'
            ):
                self.db.delete_user(username)
                self._update_admin_user_list()
                self.user_info.config(state='normal')
                self.user_info.delete(1.0, tk.END)
                self.user_info.config(state='disabled')

        except Exception as e:
            logging.error(f"Delete user error: {str(e)}")
            messagebox.showerror("Ошибка", "Не удалось удалить пользователя")

    def _update_all_messages(self):
        encryptor = RSAECCEncryptor()
        try:
            self.all_messages.config(state='normal')
            self.all_messages.delete(1.0, tk.END)

            messages = self.db.get_all_messages()
            current_user = self.auth.get_current_user()

            for msg in messages:
                try:
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(msg.timestamp))
                    header = f"[{timestamp}] {msg.sender} -> {msg.recipient}:\n"

                    if msg.sender == current_user.username:
                        self.all_messages.insert(tk.END, header, 'header')
                        self.all_messages.insert(tk.END, "<зашифровано>\n\n", 'encrypted')
                    else:
                        try:
                            decrypted = encryptor.decrypt_message(
                                json.loads(msg.encrypted_data),
                                json.loads(self.auth.get_current_user().private_key)
                                # Приватный ключ текущего пользователя
                            )

                            self.all_messages.insert(tk.END, header, 'header')
                            self.all_messages.insert(tk.END, f"{decrypted}\n\n", 'decrypted')
                        except Exception as e:
                            self.all_messages.insert(tk.END, header, 'header')
                            self.all_messages.insert(tk.END, f"<ошибка расшифровки: {str(e)}>\n\n", 'error')
                except Exception as e:
                    self.all_messages.insert(tk.END, f"[ОШИБКА] Не удалось обработать сообщение\n\n", 'error')

            self.all_messages.tag_config('header', font=('Helvetica', 9, 'bold'))
            self.all_messages.tag_config('encrypted', foreground='gray')
            self.all_messages.tag_config('decrypted', foreground='black')
            self.all_messages.tag_config('error', foreground='red')

            self.all_messages.config(state='disabled')
            self.all_messages.yview(tk.END)

        except Exception as e:
            logging.error(f"Update all messages error: {str(e)}")
            messagebox.showerror("Ошибка", "Не удалось загрузить сообщения")


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SecureMessengerApp(root)
        root.mainloop()
    except Exception as e:
        logging.critical(f"Application crash: {str(e)}\n{traceback.format_exc()}")
        messagebox.showerror("Критическая ошибка", "Приложение завершило работу")