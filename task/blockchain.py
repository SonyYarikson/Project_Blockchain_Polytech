# Убедитесь, что установлены зависимости:
# pip install ecdsa flask requests

import hashlib
import time
import json
import os
import sys
from typing import List, Dict, Set
from ecdsa import SigningKey, VerifyingKey, NIST256p
from flask import Flask, jsonify, request
import requests
import threading
from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, Frame, messagebox

class Transaction:
    def __init__(self, sender: str, recipient: str, amount: float, 
                 signature: str = None, timestamp: float = None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp or time.time()
        self.signature = signature

    def sign(self, private_key: str) -> bool:
        try:
            sk = SigningKey.from_string(bytes.fromhex(private_key), curve=NIST256p)
            message = self._get_message().encode('utf-8')
            self.signature = sk.sign(message).hex()
            return True
        except Exception as e:
            print(f"Signing error: {e}")
            return False

    def verify(self) -> bool:
        if self.sender == "0":
            return True
            
        if not self.signature:
            return False
            
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=NIST256p)
            message = self._get_message().encode('utf-8')
            return vk.verify(bytes.fromhex(self.signature), message)
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

    def _get_message(self) -> str:
        return f"{self.sender}:{self.recipient}:{self.amount:.8f}:{self.timestamp:.4f}"

    def to_dict(self) -> Dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

class Block:
    def __init__(self, index: int, previous_hash: str, transactions: List[Transaction], nonce: int = 0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = time.time()
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_data = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()

    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.mining_reward = 10
        self.difficulty = 2
        self.peers: Set[str] = set()
        self.storage_file = "blockchain_data.json"
        self.load_chain()

    def load_chain(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, "r") as f:
                data = json.load(f)
                self.chain = [
                    Block(
                        block_data["index"],
                        block_data["previous_hash"],
                        [
                            Transaction(
                                sender=tx["sender"],
                                recipient=tx["recipient"],
                                amount=tx["amount"],
                                signature=tx["signature"],
                                timestamp=tx["timestamp"]
                            ) for tx in block_data["transactions"]
                        ],
                        block_data["nonce"]
                    ) for block_data in data
                ]
            print("Blockchain loaded from file")
        else:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_key = SigningKey.generate(curve=NIST256p)
        genesis_public_key = genesis_key.get_verifying_key().to_string().hex()
        
        genesis_tx = Transaction(
            sender="0",
            recipient=genesis_public_key,
            amount=1000,
            timestamp=time.time()
        )
        genesis_tx.sign(genesis_key.to_string().hex())
        
        genesis_block = Block(0, "0", [genesis_tx])
        self.chain.append(genesis_block)
        self.save_chain()
        print("Genesis block created")

    def save_chain(self):
        with open(self.storage_file, "w") as f:
            json.dump([block.to_dict() for block in self.chain], f, indent=4)

    def add_transaction(self, transaction: Transaction) -> bool:
        if transaction.sender == "0":
            self.pending_transactions.append(transaction)
            return True
            
        if not transaction.verify():
            print("Invalid transaction signature!")
            return False
            
        if self.get_balance(transaction.sender) < transaction.amount:
            print("Insufficient funds!")
            return False
            
        self.pending_transactions.append(transaction)
        print("Transaction added to pending")
        return True

    def get_balance(self, address: str) -> float:
        balance = 0.0
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address:
                    balance -= tx.amount
                if tx.recipient == address:
                    balance += tx.amount
        return balance

    def mine_pending_transactions(self, miner_address: str) -> bool:
        if not self.pending_transactions:
            print("No transactions to mine")
            return False

        reward_tx = Transaction("0", miner_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        new_block = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].hash if self.chain else "0",
            transactions=self.pending_transactions
        )

        print(f"Mining block #{new_block.index}...")
        while new_block.hash[:self.difficulty] != "0" * self.difficulty:
            new_block.nonce += 1
            new_block.hash = new_block.calculate_hash()

        self.chain.append(new_block)
        self.pending_transactions = []
        self.save_chain()
        print(f"Block #{new_block.index} mined")
        return True

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]

            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            for tx in current.transactions:
                if not tx.verify():
                    return False
        return True

class BlockchainGUI:
    def __init__(self, root, port=5000):
        self.root = root
        self.root.title(f"Blockchain Node @ {port}")
        self.port = port
        self.blockchain = Blockchain()
        self.peers = set()
        
        self.sk = SigningKey.generate(curve=NIST256p)
        self.vk = self.sk.get_verifying_key()
        self.public_key = self.vk.to_string().hex()
        self.private_key = self.sk.to_string().hex()
        
        self.app = Flask(__name__)
        self.setup_routes()
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        
        self.create_gui()
        
    def run_server(self):
        self.app.run(port=self.port, use_reloader=False)

    def setup_routes(self):
        @self.app.route('/chain', methods=['GET'])
        def get_chain():
            return jsonify([block.to_dict() for block in self.blockchain.chain]), 200

        @self.app.route('/nodes', methods=['GET'])
        def get_nodes():
            return jsonify(list(self.blockchain.peers)), 200

        @self.app.route('/nodes/register', methods=['POST'])
        def register_node():
            values = request.get_json()
            node = values.get('node_address')

            if node is None:
                return "Error: Invalid node address", 400

            self.blockchain.peers.add(node)
            return "Node added successfully", 201

        @self.app.route('/transaction/new', methods=['POST'])
        def new_transaction():
            values = request.get_json()
            required = ['sender', 'recipient', 'amount', 'signature', 'timestamp']
            
            if not all(k in values for k in required):
                return 'Missing values', 400

            tx = Transaction(
                values['sender'],
                values['recipient'],
                values['amount'],
                values['signature'],
                values['timestamp']
            )

            if self.blockchain.add_transaction(tx):
                return "Transaction added to pending", 201
            return "Invalid transaction", 400

        @self.app.route('/mine', methods=['GET'])
        def mine():
            if self.blockchain.mine_pending_transactions(self.public_key):
                new_block = self.blockchain.chain[-1]
                self.broadcast_block(new_block)
                return "Block mined successfully", 200
            return "No transactions to mine", 400

        @self.app.route('/blocks/receive', methods=['POST'])
        def receive_block():
            block_data = request.get_json()
            transactions = [
                Transaction(
                    tx['sender'],
                    tx['recipient'],
                    tx['amount'],
                    tx['signature'],
                    tx['timestamp']
                ) for tx in block_data['transactions']
            ]

            new_block = Block(
                block_data['index'],
                block_data['previous_hash'],
                transactions,
                block_data['nonce']
            )

            if self.validate_and_add_block(new_block):
                return "Block accepted", 201
            return "Invalid block", 400

    def validate_and_add_block(self, new_block: Block) -> bool:
        last_block = self.blockchain.chain[-1]
        
        if new_block.index != last_block.index + 1:
            return False
            
        if new_block.previous_hash != last_block.hash:
            return False
            
        if new_block.hash != new_block.calculate_hash():
            return False

        for tx in new_block.transactions:
            if tx.sender != "0" and not tx.verify():
                return False

        self.blockchain.chain.append(new_block)
        self.blockchain.save_chain()
        return True

    def create_gui(self):
        wallet_frame = Frame(self.root, padx=10, pady=10)
        wallet_frame.pack(fill="x")

        Label(wallet_frame, text="Public Key:").grid(row=0, column=0, sticky="w")
        self.pub_key_entry = Entry(wallet_frame, width=70)
        self.pub_key_entry.insert(0, self.public_key)
        self.pub_key_entry.grid(row=1, column=0, columnspan=2)

        Label(wallet_frame, text="Balance:").grid(row=2, column=0, sticky="w")
        self.balance_label = Label(wallet_frame, text="0.0")
        self.balance_label.grid(row=2, column=1, sticky="e")

        trans_frame = Frame(self.root, padx=10, pady=10)
        trans_frame.pack(fill="x")

        Label(trans_frame, text="Recipient:").grid(row=0, column=0, sticky="w")
        self.recipient_entry = Entry(trans_frame, width=50)
        self.recipient_entry.grid(row=1, column=0)

        Label(trans_frame, text="Amount:").grid(row=0, column=1, sticky="w")
        self.amount_entry = Entry(trans_frame, width=15)
        self.amount_entry.grid(row=1, column=1)

        Button(trans_frame, text="Send", command=self.send_transaction).grid(row=1, column=2, padx=5)
        Button(trans_frame, text="Mine", command=self.mine_block).grid(row=1, column=3)

        net_frame = Frame(self.root, padx=10, pady=10)
        net_frame.pack(fill="x")

        Label(net_frame, text="Node Address:").grid(row=0, column=0, sticky="w")
        self.node_entry = Entry(net_frame, width=50)
        self.node_entry.grid(row=1, column=0)
        Button(net_frame, text="Connect", command=self.connect_to_node).grid(row=1, column=1, padx=5)

        log_frame = Frame(self.root, padx=10, pady=10)
        log_frame.pack(fill="both", expand=True)

        self.log_text = Text(log_frame, height=15, width=80)
        scrollbar = Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.update_display()

    def send_transaction(self):
        recipient = self.recipient_entry.get().strip()
        
        # Нормализация адреса
        recipient = ''.join(c for c in recipient if c.isalnum()).lower()
        
        if not recipient:
            messagebox.showerror("Error", "Recipient address cannot be empty")
            return
            
        if len(recipient) != 128:
            messagebox.showerror("Error", 
                f"Invalid address length: {len(recipient)} characters\n"
                f"(Required: 128 hexadecimal characters)"
            )
            return
            
        try:
            # Проверка hex-формата
            bytes.fromhex(recipient)
            # Проверка валидности ключа
            VerifyingKey.from_string(bytes.fromhex(recipient), curve=NIST256p)
        except ValueError:
            messagebox.showerror("Error", 
                "Address contains invalid characters\n"
                "(Allowed: 0-9, a-f, A-F)"
            )
            return
        except Exception as e:
            messagebox.showerror("Error", 
                f"Invalid public key structure:\n{str(e)}"
            )
            return

        try:
            amount = float(self.amount_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid amount")
            return

        if recipient == self.public_key:
            messagebox.showerror("Error", "Cannot send to yourself")
            return

        tx = Transaction(self.public_key, recipient, amount)
        if not tx.sign(self.private_key):
            messagebox.showerror("Error", "Failed to sign transaction")
            return

        if self.blockchain.add_transaction(tx):
            self.broadcast_transaction(tx)
            messagebox.showinfo("Success", "Transaction added")
            self.update_display()
        else:
            messagebox.showerror("Error", "Invalid transaction")

    def broadcast_transaction(self, tx: Transaction):
        for peer in self.blockchain.peers:
            try:
                requests.post(
                    f'http://{peer}/transaction/new',
                    json=tx.to_dict(),
                    timeout=3
                )
            except:
                continue

    def mine_block(self):
        if self.blockchain.mine_pending_transactions(self.public_key):
            new_block = self.blockchain.chain[-1]
            self.broadcast_block(new_block)
            messagebox.showinfo("Success", "New block mined!")
            self.update_display()
        else:
            messagebox.showerror("Error", "No transactions to mine")

    def broadcast_block(self, block: Block):
        for peer in self.blockchain.peers:
            try:
                requests.post(
                    f'http://{peer}/blocks/receive',
                    json=block.to_dict(),
                    timeout=3
                )
            except:
                continue

    def connect_to_node(self):
        node_address = self.node_entry.get()
        if not node_address:
            return

        try:
            response = requests.post(
                f'http://{node_address}/nodes/register',
                json={'node_address': f'localhost:{self.port}'},
                timeout=3
            )
            if response.status_code == 201:
                self.blockchain.peers.add(node_address)
                self.sync_chain()
                messagebox.showinfo("Success", f"Connected to {node_address}")
                self.update_display()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")

    def sync_chain(self):
        longest_chain = None
        max_length = len(self.blockchain.chain)

        for peer in self.blockchain.peers:
            try:
                response = requests.get(f'http://{peer}/chain', timeout=3)
                if response.status_code == 200:
                    chain_data = response.json()
                    if len(chain_data) > max_length:
                        temp_chain = []
                        valid = True
                        for block_data in chain_data:
                            block = Block(
                                block_data['index'],
                                block_data['previous_hash'],
                                [
                                    Transaction(
                                        sender=tx['sender'],
                                        recipient=tx['recipient'],
                                        amount=tx['amount'],
                                        signature=tx['signature'],
                                        timestamp=tx['timestamp']
                                    ) for tx in block_data['transactions']
                                ],
                                block_data['nonce']
                            )
                            if block.hash != block_data['hash']:
                                valid = False
                                break
                            temp_chain.append(block)

                        if valid:
                            max_length = len(chain_data)
                            longest_chain = temp_chain
            except:
                continue

        if longest_chain:
            self.blockchain.chain = longest_chain
            self.blockchain.save_chain()
            messagebox.showinfo("Sync", "Blockchain updated")
            self.update_display()

    def update_display(self):
        balance = self.blockchain.get_balance(self.public_key)
        self.balance_label.config(text=f"{balance:.2f}")

        self.log_text.delete(1.0, "end")
        self.log_text.insert("end", f"Chain length: {len(self.blockchain.chain)}\n")
        self.log_text.insert("end", f"Pending transactions: {len(self.blockchain.pending_transactions)}\n")
        self.log_text.insert("end", f"Connected nodes: {len(self.blockchain.peers)}\n\n")

        if self.blockchain.chain:
            last_block = self.blockchain.chain[-1]
            self.log_text.insert("end", f"Latest Block (#{last_block.index}):\n")
            self.log_text.insert("end", f"Hash: {last_block.hash[:16]}...\n")
            self.log_text.insert("end", f"Transactions: {len(last_block.transactions)}\n")
            for tx in last_block.transactions[-3:]:
                self.log_text.insert("end", 
                    f"  {tx.sender[:8]}... → {tx.recipient[:8]}...: {tx.amount:.2f}\n"
                )

if __name__ == "__main__":
    root = Tk()
    
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except:
            pass

    gui = BlockchainGUI(root, port)
    root.mainloop()