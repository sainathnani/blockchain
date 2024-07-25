import binascii
import datetime as date
import hashlib
import sys
from collections import OrderedDict
from io import BytesIO
from urllib.parse import urlparse
from uuid import uuid4

import pyqrcode
import requests
import rsa
import base64
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from flask import Flask, jsonify, request, render_template, session
from flask import url_for, flash, redirect
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_login import LoginManager, login_user, current_user, login_required

from config import Config
from forms import RegistrationForm, LoginForm
from models import db, User

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

CORS(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


# Modify the login route to base64 encode the QR code
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('landing'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            session['email'] = form.email.data

            # Generate public and private keys
            public_key, private_key = rsa.newkeys(512)
            user.public_key = public_key.save_pkcs1().decode('utf-8')
            user.private_key = private_key.save_pkcs1().decode('utf-8')
            db.session.commit()

            return redirect(url_for('landing'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/account')
def account():

    user = User.query.filter_by(email=session['email']).first()
    # Generate QR code for public key
    qr = pyqrcode.create(user.public_key)
    buffer = BytesIO()
    qr.png(buffer, scale=5)
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return render_template('account.html', title='Account', qr_code=qr_code_base64, email=user.email)


@app.route('/landing')
@login_required
def landing():
    return render_template('landing.html')


class Transaction:
    def __init__(self, sender_address, receiver_address, sender_private_key, amount):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.receiver_address = receiver_address
        self.amount = amount

    def to_dict(self):
        return OrderedDict({
            'sender_address': self.sender_address,
            'receiver_address': self.receiver_address,
            'amount': self.amount
        })

    # using the sender's information sign using the sender's private key
    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        hash = SHA.new(str(self.to_dict()).encode('utf8'))
        signature = binascii.hexlify(signer.sign(hash)).decode('ascii')
        return signature


class Block():
    def __init__(self, timestamp, transactions, nonce, previous_hash):
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        value = str(self.timestamp) + str(self.transactions) + str(self.nonce)
        value = value.encode('utf-8')
        return hashlib.sha256(value).hexdigest()

    def to_dict(self):
        return OrderedDict({
            'Timestamp': self.timestamp,
            'Previous Hash': self.previous_hash,
            'Hash': self.hash,
            'Nonce': self.nonce,
            'Transaction': self.transactions
        })


class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = [self.create_genesis_block()]
        self.nodes = set()
        self.users = {}  # Store users with addresses
        self.id = str(uuid4()).replace('-', '')
        self.mining_difficulty = 4
        self.mining_reward = 10

    def create_genesis_block(self):
        genBlock = Block(date.datetime.now().strftime("%Y-%m-%d %H:%M"), [], 0, '0')
        return genBlock

    def register_node(self, node):
        # Checking node_url has valid format
        parsed_url = urlparse(node)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    # add the block only if the nonce matches the proof
    def append_block(self, block):
        zero_string = '0' * self.mining_difficulty
        if (block.calculate_hash()[0:self.mining_difficulty] == zero_string):
            self.chain.append(block)

    def create_block(self, nonce, previous_hash):
        new_block = Block(date.datetime.now().strftime("%Y-%m-%d %H:%M"), self.transactions, nonce, previous_hash)
        self.transactions = []  # reset the transactions
        the_block = self.proof_of_work(new_block)  # start the proof of work

        # if the resulting proof of work is valid, add to the blockchain
        self.chain.append(the_block)
        return the_block

    def add_transaction(self, sender_address, receiver_address, signature, amount):
        transaction = OrderedDict({
            'sender_address': sender_address,
            'receiver_address': receiver_address,
            'amount': amount
        })

        if sender_address == 'the blockchain':  # we assume the sender is receiving a reward
            self.transactions.append(transaction)  # this transaction is the reward for the miner
        else:
            verify_trans = self.verify_transaction(sender_address, signature, transaction)
            if verify_trans:  # verify the transaction with the signature before adding it to the list
                self.transactions.append(transaction)  # if the transaction is verified, then add to the list
                return True
            else:
                return False

    # Verify the transaction using the sender's public key
    def verify_transaction(self, sender_address, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        hash = SHA.new(str(transaction).encode('utf8'))
        sig = verifier.verify(hash, binascii.unhexlify(str(signature)))
        return sig

    # do the proof of work on the block
    def proof_of_work(self, block):
        zero_string = '0' * self.mining_difficulty
        while (block.hash[0:self.mining_difficulty] != zero_string):
            # use the nounce to change the hash function until the difficulty is met
            block.nonce += 1
            # recalculate the hash function
            block.hash = block.calculate_hash()
        return block

    def is_valid_chain(self):
        # Very the chain
        index = 1
        while index < len(self.chain):
            current_block = self.chain[index]
            previous_block = self.chain[index - 1]

            # make sure the hash has not been tampered with, so recalculate the hash
            if current_block.hash != current_block.calculate_hash():
                return False

            # make sure the previous hash has for the current block has not been tampered with
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

    def longest_chain(self):
        neighbors = self.nodes
        new_chain = None

        max_len = len(self.chain)

        # find and verify chains from the nodes in the network
        for node in neighbors:
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['blockchain']

                if length > max_len and self.is_valid_chain():
                    max_len = length
                    new_chain = chain

        new_new_chain = []
        if new_chain:
            for block in new_chain:
                if block:
                    new_block = Block(block['Timestamp'], block['Transaction'], block['Nonce'], block['Previous Hash'])
                    new_new_chain.append(new_block)

        if new_new_chain:
            self.chain = new_new_chain
            return True
        return False


blockchain = Blockchain()


def read_valid_addresses(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()


# Check if the receiver address is valid
def is_valid_address(receiver_address):
    valid_addresses = read_valid_addresses('valid_addresses.txt')
    return receiver_address in valid_addresses


# This url works
@app.route('/transactions', methods=['GET'])
def get_transactions():
    response = {'transactions': blockchain.transactions}
    return jsonify(response), 200


# This url works
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            'Timestamp': block.timestamp,
            'Previous Hash': block.previous_hash,
            'Hash': block.hash,
            'Nonce': block.nonce,
            'Transaction': block.transactions
        })
    response = {
        'blockchain': chain_data,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route('/view', methods=['POST'])
def view_transaction():
    input = request.get_json()
    try:
        data = request.get_json(force=True)  # Ensure JSON data is present
    except Exception as e:
        return jsonify({"error": "Invalid JSON data"}), 400
    key_to_extract = "sender_address"  # Replace with the actual key in your JSON
    if key_to_extract not in data:
        return jsonify({"error": f"Key '{key_to_extract}' not found in data"}), 400
    extracted_value = data[key_to_extract]
    print(extracted_value)

    url = 'http://localhost:6001/chain'
    response = requests.get(url)
    json_data = response.json()  # Convert response to JSON
    # data = json.loads(json_data)

    matching_addresses = []
    for block in json_data['blockchain']:
        for transaction in block.get('Transaction', []):
            sender_address = transaction.get('sender_address')
            if sender_address and sender_address == extracted_value:
                matching_addresses.append(transaction)

    return jsonify(matching_addresses)


@app.route('/transactions/generate', methods=['POST'])
def generate_transaction():
    values = request.get_json()

    required = ['sender_address', 'receiver_address', 'amount', 'sender_private_key']

    if not all(k in values for k in required):
        return jsonify({'msg': 'Missing values'}), 400

    transaction = Transaction(values['sender_address'], values['receiver_address'], values['sender_private_key'],
                              values['amount'])

    response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender_address', 'receiver_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return jsonify({'msg': 'Missing values'}), 400

    transaction = blockchain.add_transaction(values['sender_address'], values['receiver_address'], values['signature'],
                                             values['amount'])
    curr_transaction = Transaction(values['sender_address'], values['receiver_address'], '123', values['amount'])

    if transaction:
        response = {'msg': 'Transaction will be added to the Block'}
        announce_new_transaction(curr_transaction)
        return jsonify(response), 200
    else:
        response = {'msg': 'Invalid Transaction'}
        return jsonify(response), 406


@app.route('/mine', methods=['GET'])
def mine():
    # get the last block of the chain, it is the one we have to mine
    last_block = blockchain.chain[-1]

    # do the proof of work

    previous_hash = last_block.hash

    # check if the transaction list is 0
    if len(blockchain.transactions) == 0:
        return jsonify({'msg': 'No transactions to mine'}), 400

    # add the transaction of the reward to the miner
    blockchain.add_transaction(sender_address='the blockchain', receiver_address=blockchain.id, signature='',
                               amount=0.1)
    # do the proof of work on the new block
    new_block = blockchain.create_block(0, previous_hash)

    # announce the block to other users
    announce_new_block(new_block)

    response = {
        'msg': 'New block forged',
        'hash': new_block.hash,
        'previous_hash': new_block.previous_hash,
        'nonce': new_block.nonce,
        'transactions': new_block.transactions
    }
    return jsonify(response), 200


# This URL works
@app.route('/nodes/resolve', methods=['GET'])
def consenus():
    replaced = blockchain.longest_chain()

    if replaced:
        chain_data = []
        for block in blockchain.chain:
            chain_data.append({
                'Timestamp': block.timestamp,
                'Previous Hash': block.previous_hash,
                'Hash': block.hash,
                'Nonce': block.nonce,
                'Transaction': block.transactions
            })
            response = {
                'msg': 'The Blockchain has been replaced',
                'chain': chain_data
            }
    else:
        chain_data = []
        for block in blockchain.chain:
            chain_data.append({
                'Timestamp': block.timestamp,
                'Previous Hash': block.previous_hash,
                'Hash': block.hash,
                'Nonce': block.nonce,
                'Transaction': block.transactions
            })
            response = {
                'msg': 'Our Blockchain is fine',
                'chain': chain_data
            }
    return jsonify(response), 200


@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    trans_data = request.get_json()

    transaction = OrderedDict({
        'sender_address': trans_data['sender_address'],
        'reciever_address': trans_data['receiver_address'],
        'amount': trans_data['amount']
    })

    blockchain.transactions.append(transaction)
    return jsonify({'msg': 'The transaction is added to the chain'}), 200


@app.route('/add_block', methods=['POST'])
def add_block():
    block_data = request.get_json()
    block = Block(block_data['Timestamp'], block_data['Transaction'], block_data['Nonce'], block_data['Previous Hash'])
    blockchain.chain.append(block)
    return jsonify({'msg': 'The mined block is added to our chain'}), 200


# Works
@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {
        'nodes': nodes
    }
    return jsonify(response), 200


# Works
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes').replace(' ', '').split(',')
    if nodes == None:
        return jsonify({'msg': 'Return a valid list of nodes'}), 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'msg': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }

    return jsonify(response), 201


def announce_new_block(block):
    for peer in blockchain.nodes:
        url = "http://{}/add_block".format(peer)
        requests.post(url, json={
            'Timestamp': block.timestamp,
            'Previous Hash': block.previous_hash,
            'Hash': block.hash,
            'Nonce': block.nonce,
            'Transaction': block.transactions
        })


def announce_new_transaction(transaction):
    for peer in blockchain.nodes:
        url = "http://{}/add_transaction".format(peer)
        requests.post(url, json={
            'sender_address': transaction.sender_address,
            'receiver_address': transaction.receiver_address,
            'amount': transaction.amount
        })


if __name__ == '__main__':
    port_num = sys.argv[1]
    app.run(debug=True, port=int(port_num))
