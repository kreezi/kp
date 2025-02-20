import os
import sys
# Добавляем корневую папку проекта в пути
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import threading
import grpc
from server import chat_pb2, chat_pb2_grpc
from PyQt6.QtGui import QPixmap, QFont, QIcon, QPalette, QColor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QFormLayout, QWidget, QFrame, QComboBox, QHBoxLayout, QListWidget, QAbstractItemView, QTextEdit,
    QMessageBox, QFileDialog, QSplitter
)
from PyQt6.QtCore import Qt

from algorithm import deffiehellman, rc5, mars, cryptoContext as cc

algo_dict = {
    "rc5": rc5.RC5(w=64, R=20, key=b"12345678"),
    "mars": mars.Mars(key=b'mykeys1231245677'),
}

padding_dict = {
    "PKCS7": cc.PaddingScheme.PKCS7,
    "ZERO": cc.PaddingScheme.ZERO,
    "ISO7816": cc.PaddingScheme.ISO7816,
}

class GRPCClient:
    def __init__(self):
        self.channel = grpc.insecure_channel("localhost:8090")
        self.auth_stub = chat_pb2_grpc.AuthServiceStub(self.channel)
        self.chat_stub = chat_pb2_grpc.ChatServiceStub(self.channel)

        self.username = None

        self.key_rooms = {} #room_id: {public_key: private: session: }
        self.cryptoContext = {} #room_id: cryptoContext

    def set_username(self, username):
        self.username = username

class LoginWindow(QMainWindow):
    def __init__(self, grpc_client):
        super().__init__()
        self.grpc_client = grpc_client
        self.setWindowTitle("Log/Reg")
        self.setGeometry(200, 200, 400, 300)

        # Основной контейнер
        container = QWidget()
        layout = QVBoxLayout(container)
        self.setCentralWidget(container)

        # Стилизация
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                font-size: 14px;
                color: #333;
            }
            QLineEdit {
                font-size: 14px;
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }
            QPushButton {
                font-size: 14px;
                padding: 10px;
                background-color: #007bff;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:pressed {
                background-color: #004080;
            }
        """)

        # Логотип
        logo_label = QLabel(self)
        logo_path = "images/logoAdidas.jpg"

        if QPixmap(logo_path).isNull():
            logo_label.setText("Добро пожаловать!")
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            logo_label.setStyleSheet("font-size: 16px; color: #666;")
        else:
            logo_label.setPixmap(QPixmap(logo_path))
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Поля ввода и кнопки
        self.login_label = QLabel("Login:")
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText("Enter your username")

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_button = QPushButton("Login")
        self.register_button = QPushButton("Register")

        # Добавляем элементы в layout
        layout.addWidget(logo_label)
        layout.addWidget(self.login_label)
        layout.addWidget(self.login_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        # Отступы и выравнивание
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)

        # Сигналы для кнопок
        self.login_button.clicked.connect(self.handle_login)
        self.register_button.clicked.connect(self.handle_register)

    def handle_login(self):
        username = self.login_input.text()
        password = self.password_input.text()
        try:
            response = self.grpc_client.auth_stub.Login(
                chat_pb2.AuthRequest(username=username, password=password)
            )
            print(f"Login successful. Token: {response.token}")

            self.grpc_client.set_username(username)  # Сохраняем имя пользователя

            # После успешного входа показываем окно чата
            self.chat_window = ChatWindow(self.grpc_client)
            self.chat_window.show()

            # Закрываем окно входа
            self.close()
        except grpc.RpcError as e:
            print(f"Login failed: {e.code()} - {e.details()}")
        except Exception as e:
            print(f"Unexpected error during login: {e}")

    def handle_register(self):
        username = self.login_input.text()
        password = self.password_input.text()
        try:
            response = self.grpc_client.auth_stub.Register(
                chat_pb2.AuthRequest(username=username, password=password)
            )
            print(f"Registration successful. Token: {response.token}")
        except grpc.RpcError as e:
            print(f"Registration failed: {e.code()} - {e.details()}")
        except Exception as e:
            print(f"Unexpected error during registration: {e}")

class CreateRoomWindow(QMainWindow):
    def __init__(self, grpc_client):
        super().__init__()
        self.grpc_client = grpc_client
        self.setWindowTitle("Create Room")
        self.setGeometry(300, 300, 450, 400)

        # Основной макет
        layout = QVBoxLayout()
        layout.setSpacing(15)  # Увеличим расстояние между элементами

        # Заголовок
        header_label = QLabel("Create new chat room")
        header_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #333;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Алгоритм
        self.algorithm_label = QLabel("Algorithm:")
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["RC5", "Mars"])
        self.algorithm_combo.setStyleSheet(self._get_combo_style())

        # Режим шифрования
        self.mode_label = QLabel("Encryption mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["ECB", "CFB", "OFB", "CBC", "CTR"])
        self.mode_combo.setStyleSheet(self._get_combo_style())

        # Режим набивки
        self.padding_label = QLabel("Padding mode:")
        self.padding_combo = QComboBox()
        self.padding_combo.addItems(["PKCS7", "ZERO", "ISO7816"])
        self.padding_combo.setStyleSheet(self._get_combo_style())

        # Имя чата
        self.chat_name_label = QLabel("Chat name:")
        self.chat_name_input = QLineEdit()
        self.chat_name_input.setPlaceholderText("Enter chat name")
        self.chat_name_input.setStyleSheet("""
            QLineEdit {
                font-size: 14px;
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QLineEdit:focus {
                border: 1px solid #007BFF;
            }
        """)

        # Кнопка создания
        self.create_button = QPushButton("Create")
        self.create_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                font-size: 16px;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)

        # Упаковка виджетов в макет
        layout.addWidget(self.algorithm_label)
        layout.addWidget(self.algorithm_combo)
        layout.addWidget(self.mode_label)
        layout.addWidget(self.mode_combo)
        layout.addWidget(self.padding_label)
        layout.addWidget(self.padding_combo)
        layout.addWidget(self.chat_name_label)
        layout.addWidget(self.chat_name_input)
        layout.addWidget(self.create_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Основной контейнер
        container = QWidget()
        container.setLayout(layout)
        container.setStyleSheet("""
            QWidget {
                background-color: #f5f5f5;
                padding: 15px;
            }
        """)
        self.setCentralWidget(container)

        # Подключение сигнала
        self.create_button.clicked.connect(self.handle_create)

    def _get_combo_style(self):
        """Возвращает стили для QComboBox."""
        return """
            QComboBox {
                font-size: 14px;
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 5px;
                background-color: white;
            }
            QComboBox:focus {
                border: 1px solid #007BFF;
            }
        """

    def handle_create(self):
        algorithm = self.algorithm_combo.currentText()
        mode = self.mode_combo.currentText()
        padding = self.padding_combo.currentText()
        chat_name = self.chat_name_input.text()
        try:
            response = self.grpc_client.chat_stub.CreateRoom(
                chat_pb2.CreateRoomRequest(room_id=chat_name, algorithm=algorithm, mode=mode, padding=padding)
            )
            print(f"Room created: {response.message}")

            # Закрываем окно
            self.close()
        except grpc.RpcError as e:
            print(f"Create Room failed: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during create room: {e}")

class JoinRoomWindow(QMainWindow):
    def __init__(self, grpc_client, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.grpc_client = grpc_client
        self.setWindowTitle("Join Room")
        self.setGeometry(300, 300, 400, 250)

        # Основной макет
        layout = QVBoxLayout()
        layout.setSpacing(15)  # Расстояние между элементами

        # Заголовок
        header_label = QLabel("Присоединение к чату")
        header_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #333;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(header_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Название чата
        self.room_name_label = QLabel("Название чата:")
        self.room_name_input = QLineEdit()
        self.room_name_input.setPlaceholderText("Введите имя чата")
        self.room_name_input.setStyleSheet("""
            QLineEdit {
                font-size: 14px;
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QLineEdit:focus {
                border: 1px solid #007BFF;
            }
        """)

        # Кнопка "Присоединиться"
        self.join_button = QPushButton("Присоединиться")
        self.join_button.setStyleSheet("""
            QPushButton {
                background-color: #007BFF;
                color: white;
                font-size: 16px;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)

        # Упаковка виджетов
        layout.addWidget(self.room_name_label)
        layout.addWidget(self.room_name_input)
        layout.addWidget(self.join_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Основной контейнер
        container = QWidget()
        container.setLayout(layout)
        container.setStyleSheet("""
            QWidget {
                background-color: #f5f5f5;
                padding: 15px;
            }
        """)
        self.setCentralWidget(container)

        # Подключение сигнала
        self.join_button.clicked.connect(self.handle_join)

    def handle_join(self):
        room_name = self.room_name_input.text()
        if not room_name:
            print("Please enter a room name.")
            return

        try:
            # Получаем p и g от сервера
            join_response = self.grpc_client.chat_stub.JoinRoom(chat_pb2.JoinRoomRequest(room_id=room_name, username=self.grpc_client.username))
            try:
                p = int.from_bytes(join_response.p, byteorder="big")
            except OverflowError:
                print("Ошибка: число слишком большое для преобразования.")
                return
            g = join_response.g

            # Генерируем ключи
            private_key, public_key = deffiehellman.diffie_hellman(p, g)

            # Сохраняем ключи
            self.grpc_client.key_rooms[room_name] = {
                "p": p,
                "g": g,
                "private_key": private_key,
                "public_key": public_key,
                "session_key": None
            }

            # Отправляем публичный ключ серверу
            room_response = self.grpc_client.chat_stub.SendPublicKey(chat_pb2.SendPublicKeyRequest(
                room_id=room_name,
                username=self.grpc_client.username,
                public_key=public_key.to_bytes((public_key.bit_length() + 7) // 8, byteorder='big')
            ))

            # Сообщаем родительскому окну, что комната присоединена
            self.parent.chat_list.append(f"Joined room: {room_name}")
            self.parent.active_room = room_name

            # Добавляем комнату в список подключенных
            if room_name not in self.parent.connected_rooms:
                self.parent.connected_rooms.append(room_name)
                self.parent.update_room_list()


            # Инициализация контекста шифрования
            if room_response.mode in ["CBC", "CFB", "OFB"]:
                iv = b"1234567890abcdef"  # 16 байт
                self.grpc_client.cryptoContext[room_response.room_id] = cc.CryptoContext(
                    algo_dict[room_response.algorithm.lower()],
                    room_response.mode.upper(),
                    padding_dict[room_response.padding.upper()],
                    iv,
                )
            elif room_response.mode == "CTR":
                nonce = 12345  # Можно хранить и обновлять в БД
                nonce_bytes = nonce.to_bytes(8, 'big')
                self.grpc_client.cryptoContext[room_response.room_id] = cc.CryptoContext(
                    algo_dict[room_response.algorithm.lower()],
                    room_response.mode.upper(),
                    padding_dict[room_response.padding.upper()],
                    nonce=nonce_bytes,
                )
            else:
                self.grpc_client.cryptoContext[room_response.room_id] = cc.CryptoContext(
                    algo_dict[room_response.algorithm.lower()],
                    room_response.mode.upper(),
                    padding_dict[room_response.padding.upper()],
                )

            # Запускаем поток получения сообщений
            threading.Thread(target=self.parent.receive_messages, args=(self.parent.active_room,), daemon=True).start()

            self.close()  # Закрываем окно присоединения

            print(f"Публичный ключ отправлен: {room_response.message} и пользователь {self.grpc_client.username} присоединен к команте: {room_name}")
        except grpc.RpcError as e:
            print(f"Ошибка присоединения к комнате: {e.code()} - {e.details()}")
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")

class ChatWindow(QMainWindow):
    def __init__(self, grpc_client):
        super().__init__()
        self.grpc_client = grpc_client
        self.username = self.grpc_client.username  # Имя текущего пользователя
        self.setWindowTitle("Chat Application")
        self.setGeometry(200, 200, 1000, 350)

        # Новый атрибут для хранения сообщений по комнатам
        self.room_messages = {}  # {room_name: [messages]}
        self.send_button_state = {}  # Храним состояние кнопки для каждой комнаты

        # Новый атрибут для хранения списка подключенных комнат
        self.connected_rooms = []
        self.active_room = None
        # Новый атрибут для хранения состояния сессионного ключа
        self.session_key_generated = False

        # Основной макет окна
        main_layout = QVBoxLayout()

        # Верхняя панель (заголовок и пользовательская информация)
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        logo_path = "images/logoAdidas.jpg"
        if QPixmap(logo_path).isNull():
            logo_label.setText("Chat App")
            logo_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        else:
            logo_label.setPixmap(QPixmap(logo_path).scaled(40, 40, Qt.AspectRatioMode.KeepAspectRatio))
        header_layout.addWidget(logo_label)

        self.user_label = QLabel(f"Пользователь: {self.username}")
        self.user_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.user_label.setStyleSheet("font-size: 14px; color: #444;")
        header_layout.addWidget(self.user_label)

        # Основная панель с разделением списка комнат и чата
        content_splitter = QSplitter()
        content_splitter.setOrientation(Qt.Orientation.Horizontal)

        # Левая панель (Список комнат)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        self.room_list_widget = QListWidget()
        self.room_list_widget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.room_list_widget.setStyleSheet("font-size: 14px; padding: 5px; border: 1px solid #ccc;")
        left_layout.addWidget(QLabel("Комнаты"))
        left_layout.addWidget(self.room_list_widget)

        self.room_list_widget.clicked.connect(self.handle_room_selection)

        # Кнопки управления комнатами
        room_buttons_layout = QHBoxLayout()
        self.create_chat_button = QPushButton("Создать")
        self.join_chat_button = QPushButton("Подключиться")
        self.leave_chat_button = QPushButton("Выйти")
        for btn in [self.create_chat_button, self.join_chat_button, self.leave_chat_button]:
            btn.setStyleSheet("padding: 8px; font-size: 12px;")
            room_buttons_layout.addWidget(btn)
        left_layout.addLayout(room_buttons_layout)

        content_splitter.addWidget(left_panel)

        # Правая панель (Чат)
        right_panel = QWidget()
        chat_layout = QVBoxLayout(right_panel)

        self.chat_list = QTextEdit()
        self.chat_list.setReadOnly(True)
        self.chat_list.setStyleSheet("font-size: 14px; background-color: #fff; border: 1px solid #ccc;")
        chat_layout.addWidget(self.chat_list)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Введите сообщение...")
        self.message_input.setStyleSheet("font-size: 14px; padding: 8px; border: 1px solid #ccc;")
        chat_layout.addWidget(self.message_input)

        send_layout = QHBoxLayout()
        self.attach_button = QPushButton("📎")
        self.attach_button.setStyleSheet("font-size: 16px; padding: 5px;")
        self.send_button = QPushButton("Отправить")
        self.send_button.setStyleSheet("font-size: 14px; padding: 10px; background-color: #007bff; color: white;")
        send_layout.addWidget(self.attach_button)
        send_layout.addWidget(self.send_button)
        chat_layout.addLayout(send_layout)

        self.generate_key_button = QPushButton("Сгенерировать ключ")
        self.generate_key_button.setStyleSheet("font-size: 14px; padding: 10px; background-color: #28a745; color: white;")
        chat_layout.addWidget(self.generate_key_button)

        content_splitter.addWidget(right_panel)
        main_layout.addLayout(header_layout)
        main_layout.addWidget(content_splitter)

        # Основной виджет
        main_widget = QWidget()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Логика для обновления списка комнат
        self.update_room_list()

        # Соединение сигналов с кнопками
        self.send_button.clicked.connect(self.handle_send)
        self.create_chat_button.clicked.connect(self.handle_create_room)
        self.join_chat_button.clicked.connect(self.handle_join_room)
        self.leave_chat_button.clicked.connect(self.handle_leave_room)
        self.generate_key_button.clicked.connect(self.handle_generate_key)
        self.attach_button.clicked.connect(self.handle_attach_file)

    def update_room_list(self):
        """Обновить список комнат в выпадающем меню и список комнат на левой панели."""
        self.room_list_widget.clear()
        self.room_list_widget.addItems(self.connected_rooms)

    def handle_room_selection(self):
        """Обрабатывает выбор комнаты из списка и открывает чат."""
        selected_item = self.room_list_widget.currentItem()
        if selected_item:
            room_name = selected_item.text()
            self.active_room = room_name

            # Очищаем текущие сообщения
            self.chat_list.clear()

            # Отображаем сообщения для выбранной комнаты
            if room_name in self.room_messages:
                for message in self.room_messages[room_name]:
                    self.chat_list.append(message)

            # Активируем/деактивируем кнопку в зависимости от состояния сессионного ключа
            self.send_button.setEnabled(self.send_button_state.get(room_name, False))

    def receive_messages(self, room_id):
        """Подписывается на получение сообщений и выводит их."""
        try:
            for response in self.grpc_client.chat_stub.ReceiveMessages(chat_pb2.RoomRequest(room_id=room_id, username=self.grpc_client.username)):
                print(f"[{response.sender}]: {response.encrypted_message}")

                if self.grpc_client.username != response.sender:
                    if response.image_data:
                        #Обработка изображений
                        encrypted_image_path = f"[{response.sender}]received_encrypted_image.enc"
                        with open(encrypted_image_path, "wb") as encrypted_file:
                            encrypted_file.write(response.image_data)
                        print(f"Encrypted image saved to {encrypted_image_path}")

                        decrypted_image_path = f"[{response.sender}]decrypted_image.jpg"
                        self.grpc_client.cryptoContext[self.active_room].decrypt_file(encrypted_image_path, decrypted_image_path)
                        print(f"Image decrypted and saved to {decrypted_image_path}")

                        message = f'{response.sender}: <img src="{decrypted_image_path}" width="200" /><br>'
                    else:
                        #Обработка текста
                        if response.sender != "System":
                            decrypted_message = self.grpc_client.cryptoContext[room_id].decrypt(response.encrypted_message)
                        else:
                            decrypted_message = response.encrypted_message

                        message = f"{response.sender}: {decrypted_message.decode()}"

                    # Добавляем сообщение в список для текущей комнаты
                    if room_id not in self.room_messages:
                        self.room_messages[room_id] = []
                    self.room_messages[room_id].append(message)

                    # Если это активная комната, отображаем сообщение
                    if self.active_room == room_id:
                        self.chat_list.append(message)
        except grpc.RpcError as e:
            print(f"Error receiving messages: {e.details()}")

    def handle_send(self):
        """Отправляет сообщение в очередь комнаты."""
        message = self.message_input.text()
        if not message:
            return

        message_encode = self.grpc_client.cryptoContext[self.active_room].encrypt(message.encode())

        try:
            def message_iterator():
                msg = chat_pb2.MessageRequest(
                    room_id=self.active_room,
                    sender=self.grpc_client.username,
                    encrypted_message=message_encode,
                    image_data=b'',
                )
                print("Yielding message:", msg, "\n\n")
                yield msg

            try:
                response = self.grpc_client.chat_stub.SendMessage(message_iterator())
                for data in response:
                    print("Response from server:", data)
            except grpc.RpcError as e:
                print(f"Failed to send message: {e.code()}: {e.details()}")

            # Добавляем сообщение в список для текущей комнаты
            if self.active_room not in self.room_messages:
                self.room_messages[self.active_room] = []
            self.room_messages[self.active_room].append(f"Вы: {message}")

            # Отображаем сообщение, если это активная комната
            if self.active_room == self.active_room:
                self.chat_list.append(f"Вы: {message}")

            self.message_input.clear()
        except grpc.RpcError as e:
            print(f"Failed to send message: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during message sending: {e}")

    def handle_attach_file(self):
        """Открывает диалоговое окно для выбора файла и отправляет его на сервер (текстовые файлы или изображения)."""
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFiles)
        file_dialog.setNameFilter("Text files (*.txt);;Images (*.png *.xpm *.jpg *.jpeg *.gif)")
        file_dialog.setViewMode(QFileDialog.ViewMode.List)

        if file_dialog.exec():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                file_path = selected_files[0]
                if file_path.endswith('.txt'):
                    self.send_text_file(file_path)
                else:
                    self.send_image(file_path)

    def send_text_file(self, file_path):
        """Отправляет текстовый файл в текущую комнату."""
        try:
            # Читаем текстовый файл в байты
            with open(file_path, 'rb') as file:
                file_data = file.read()

            # Шифруем файл перед отправкой
            encrypted_file_data = self.grpc_client.cryptoContext[self.active_room].encrypt(file_data)

            def message_iterator():
                msg = chat_pb2.MessageRequest(
                    room_id=self.active_room,
                    sender=self.grpc_client.username,
                    encrypted_message=encrypted_file_data,
                    image_data=b'',
                )
                yield msg

            try:
                response = self.grpc_client.chat_stub.SendMessage(message_iterator())
                print("Response from server:", response)
            except grpc.RpcError as e:
                print(f"Failed to send text file: {e.code()}: {e.details()}")

            # Формируем сообщение с текстовым файлом
            message = f'отправили текстовый файл: {file_path}</a>'

            # Добавляем сообщение в список для текущей комнаты
            if self.active_room not in self.room_messages:
                self.room_messages[self.active_room] = []
            self.room_messages[self.active_room].append(f"Вы: {message}")

            # Отображаем сообщение, если это активная комната
            if self.active_room == self.active_room:
                self.chat_list.append(f"Вы: {message}")

        except grpc.RpcError as e:
            print(f"Failed to send text file: {e.code()}: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during text file sending: {e}")

    def send_image(self, image_path):
        """Отправляет изображение в текущую комнату."""
        try:
            #Сначала идет шифрвоание изображения
            self.grpc_client.cryptoContext[self.active_room].encrypt_file(image_path, f"{image_path[:image_path.find(".")]}_encrypt{image_path[image_path.find("."):]}")
            print("йоу я зашиффровалось")

            # Прочитаем изображение в байты
            with open(f"{image_path[:image_path.find(".")]}_encrypt{image_path[image_path.find("."):]}", "rb") as image_file:
                image_data = image_file.read()


            def message_iterator():
                msg = chat_pb2.MessageRequest(
                    room_id=self.active_room,
                    sender=self.grpc_client.username,
                    encrypted_message=b'',
                    image_data=image_data,
                )
                #print("Yielding message:", msg)
                yield msg

            try:
                response = self.grpc_client.chat_stub.SendMessage(message_iterator())
                print("Response from server:", response)
            except grpc.RpcError as e:
                print(f"Failed to send message: {e.code()}: {e.details()}")

            message = f'<img src="{image_path}" width="200" /><br>'

            # Добавляем сообщение в список для текущей комнаты
            if self.active_room not in self.room_messages:
                self.room_messages[self.active_room] = []
            self.room_messages[self.active_room].append(f"Вы: {message}")

            # Отображаем сообщение, если это активная комната
            if self.active_room == self.active_room:
                self.chat_list.append(f"Вы: {message}")

        except grpc.RpcError as e:
            print(f"Failed to send image: {e.code()}: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during image sending: {e}")

    def handle_create_room(self):
        """Создает комнату через отдельный класс."""
        self.create_room_window = CreateRoomWindow(self.grpc_client)
        self.create_room_window.show()

    def handle_join_room(self):
        """Присоединение к комнате."""
        self.join_room_window = JoinRoomWindow(self.grpc_client, parent=self)
        self.join_room_window.show()

    def handle_generate_key(self):
        """Генерирует сессионный ключ для комнаты."""
        if self.active_room:
            try:
                response = self.grpc_client.chat_stub.GenerateSessionKey(
                    chat_pb2.GenerateKeyRequest(room_id=self.active_room, username=self.grpc_client.username)
                )

                other_public_key = int.from_bytes(response.other_public_key, byteorder='big')

                shared_secret = deffiehellman.compute_shared_secret(other_public_key, self.grpc_client.key_rooms[self.active_room]['private_key'], self.grpc_client.key_rooms[self.active_room]['p'])
                hash_shared_key = deffiehellman.hash_shared_key(shared_secret)

                self.grpc_client.key_rooms[self.active_room]['session_key'] = hash_shared_key
                self.grpc_client.cryptoContext[self.active_room].set_key(hash_shared_key)
                self.send_button_state[self.active_room] = True

                # Активируем кнопку, если эта комната сейчас выбрана
                if self.active_room:
                    self.send_button.setEnabled(True)
            except grpc.RpcError as e:
                print(f"Ошибка генерации ключа: {e.details()}")
            except Exception as e:
                print(f"Неожиданная ошибка: {e}")

    def handle_leave_room(self):
        """Выходит из комнаты."""
        room_name = self.active_room
        if not room_name:
            print("Please enter a room name.")
            return

        try:
            response = self.grpc_client.chat_stub.LeaveRoom(
                chat_pb2.RoomRequest(room_id=room_name, username=self.grpc_client.username)
            )
            print(f"Left room: {response.message}")

            if room_name in self.connected_rooms:
                self.connected_rooms.remove(room_name)
                self.update_room_list()

            # Удаляем сообщения для этой комнаты
            if room_name in self.room_messages:
                del self.room_messages[room_name]

            # Убираем состояние кнопки
            if room_name in self.send_button_state:
                del self.send_button_state[room_name]

            # Очищаем отображение чата
            self.chat_list.clear()

            # Переключаемся на другую комнату, если есть подключенные
            if self.connected_rooms:
                self.active_room = self.connected_rooms[0]
                self.handle_room_selection()
            else:
                self.active_room = None
                self.send_button.setEnabled(False)


        except grpc.RpcError as e:
            print(f"Leave room failed: {e.details()}")
        except Exception as e:
            print(f"Unexpected error during room leave: {e}")

class MainApp:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.grpc_client = GRPCClient()

        # Начальное окно
        self.login_window = LoginWindow(self.grpc_client)
        self.login_window.show()

    def run(self):
        sys.exit(self.app.exec())

if __name__ == "__main__":
    app = MainApp()
    app.run()
