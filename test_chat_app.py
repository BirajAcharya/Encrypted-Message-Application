import unittest
from unittest.mock import MagicMock, patch
import json
import os
import time
from chat_app import EncryptedChatApp  # Make sure chat_app.py is in the same folder or in PYTHONPATH


class TestEncryptedChatApp(unittest.TestCase):
    def setUp(self):
        # Patch Tkinter.Tk to avoid opening GUI windows during tests
        patcher = patch('tkinter.Tk')
        self.mock_tk = patcher.start()
        self.addCleanup(patcher.stop)

        # Provide a dummy root for after() calls
        self.mock_root = MagicMock()
        self.mock_tk.return_value = self.mock_root

        # Create app instance
        self.app = EncryptedChatApp()

        # Mock GUI-dependent methods to avoid side effects and GUI interaction
        self.app.display_message = MagicMock()
        self.app.update_status = MagicMock()
        self.app.message_entry = MagicMock()
        self.app.message_entry.get.return_value = ''
        self.app.message_entry.delete = MagicMock()
        self.app.send_button = MagicMock()
        self.app.username_entry = MagicMock()
        self.app.chat_area = MagicMock()

        self.app.connected = False
        self.app.peer_socket = None

    def test_set_username_updates_and_displays(self):
        self.app.username_entry.get.return_value = 'Alice  '
        self.app.set_username()
        self.assertEqual(self.app.username, 'Alice')
        self.app.display_message.assert_called_with('Username set to: Alice', 'SYSTEM')

    def test_send_message_skips_if_not_connected(self):
        self.app.connected = False
        self.app.peer_socket = MagicMock()
        self.app.message_entry.get.return_value = 'Hello'
        self.app.send_message()
        self.app.peer_socket.send.assert_not_called()

    def test_send_message_encrypts_and_sends(self):
        self.app.connected = True
        self.app.peer_socket = MagicMock()
        self.app.username = "Tester"
        self.app.message_entry.get.return_value = 'Secret Message'

        self.app.send_message()

        self.assertTrue(self.app.peer_socket.send.called)

        sent_data = self.app.peer_socket.send.call_args[0][0]
        decrypted = self.app.cipher.decrypt(sent_data)
        message_data = json.loads(decrypted.decode())
        self.assertEqual(message_data['message'], 'Secret Message')
        self.assertEqual(message_data['sender'], "Tester")

        self.app.display_message.assert_called_with('Secret Message', 'You', message_data['timestamp'])
        self.app.message_entry.delete.assert_called_once_with(0, 'end')

    def test_receive_messages_decrypt_and_display(self):
        test_message_data = {
            'sender': 'PeerUser',
            'message': 'Hello from peer',
            'timestamp': '2023-08-01 10:00:00'
        }
        raw_json = json.dumps(test_message_data).encode()
        encrypted_message = self.app.cipher.encrypt(raw_json)

        self.app.connected = True
        self.app.peer_socket = MagicMock()
        self.app.peer_socket.recv = MagicMock(side_effect=[encrypted_message, b''])

        # Patch root.after to immediately call the function
        self.app.root.after = lambda ms, func=None: func()

        self.app.save_to_history = MagicMock()

        self.app.receive_messages()

        # Allow some time for daemon thread to run
        time.sleep(0.1)

        self.app.display_message.assert_any_call('Hello from peer', 'PeerUser', '2023-08-01 10:00:00')
        self.app.save_to_history.assert_called_with('PeerUser', 'Hello from peer', '2023-08-01 10:00:00')

    def test_save_to_history_creates_file_and_append(self):
        temp_history = 'test_chat_history.txt'
        self.app.history_file = temp_history

        if os.path.exists(temp_history):
            os.remove(temp_history)

        time_str = '2025-01-01 00:00:00'
        self.app.save_to_history('Tester', 'Test message', time_str)

        with open(temp_history, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn(f'[{time_str}] Tester: Test message', content)

        os.remove(temp_history)

    def test_load_chat_history_displays_history(self):
        temp_history = 'test_chat_history.txt'
        sample_history = "[2025-01-01 00:00:00] Tester: Saved message\n"
        self.app.history_file = temp_history

        with open(temp_history, 'w', encoding='utf-8') as f:
            f.write(sample_history)

        self.app.chat_area.config = MagicMock()
        self.app.chat_area.delete = MagicMock()
        self.app.chat_area.insert = MagicMock()
        self.app.chat_area.see = MagicMock()

        self.app.load_chat_history()

        self.app.chat_area.delete.assert_called()
        self.app.chat_area.insert.assert_any_call('end', '📜 Previous Chat History:\n')
        self.app.chat_area.insert.assert_any_call('end', sample_history)
        self.app.chat_area.see.assert_called()

        os.remove(temp_history)

    def test_disconnect_closes_sockets_and_updates_ui(self):
        peer_socket_mock = MagicMock()
        server_socket_mock = MagicMock()
        self.app.peer_socket = peer_socket_mock
        self.app.server_socket = server_socket_mock
        self.app.connected = True

        self.app.update_status = MagicMock()
        self.app.display_message = MagicMock()
        self.app.message_entry = MagicMock()
        self.app.send_button = MagicMock()

        self.app.disconnect()

        peer_socket_mock.close.assert_called_once()
        server_socket_mock.close.assert_called_once()
        self.assertIsNone(self.app.peer_socket)
        self.assertIsNone(self.app.server_socket)

        self.app.update_status.assert_called_with("Disconnected", "red")
        self.app.display_message.assert_any_call("Disconnected", "SYSTEM")
        self.app.message_entry.config.assert_called_with(state='disabled')
        self.app.send_button.config.assert_called_with(state='disabled')
        self.assertFalse(self.app.connected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
