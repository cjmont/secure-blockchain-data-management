from flask import Flask, request, jsonify, session
from web3 import Web3
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import os
import logging
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import timedelta
from flask_cors import CORS

# Configurar logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Configurar CORS
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# Configurar CSRF Protection
csrf = CSRFProtect(app)

# Conectar a Avalanche
logger.info("Connecting to Avalanche...")
w3 = Web3(Web3.HTTPProvider('https://api.avax.network/ext/bc/C/rpc'))

# Cargar contrato
with open('MultiCompanyDataStorage.abi', 'r') as file:
    abi = json.load(file)

contract_address = os.getenv('CONTRACT_ADDRESS')
logger.debug(f"Contract address: {contract_address}")
contract = w3.eth.contract(address=contract_address, abi=abi)

# Configurar cuenta
private_key = os.getenv('PRIVATE_KEY')
account = w3.eth.account.from_key(private_key)

@app.route('/0x48e1b09fd922b871f5585f10d17f403afe896ce2756a057fc1b340ad48f3fc16', methods=['POST'])
@csrf.exempt
def generate_csrf_token():
    logger.info("Generating CSRF token")
    
    data = request.json
    duration_hours = data.get('duration_hours', 1)  # Valor predeterminado de 1 hora

    token = generate_csrf()
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=duration_hours)
    session.modified = True
    
    logger.debug(f"CSRF token: {token}, Duration: {duration_hours} hours")
    return jsonify({'csrf_token': token, 'duration_hours': duration_hours})


def encrypt_data(data_id, data):
    logger.debug(f"Encrypting data: data_id={data_id}, data={data}")
    key = hashlib.sha256(data_id.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    encrypted_data = json.dumps({'iv': iv, 'ciphertext': ct})
    logger.debug(f"Encrypted data: {encrypted_data}")
    return encrypted_data

def decrypt_data(data_id, encrypted_data):
    logger.debug(f"Decrypting data: data_id={data_id}, encrypted_data={encrypted_data}")
    key = hashlib.sha256(data_id.encode()).digest()
    b64 = json.loads(encrypted_data)
    iv = base64.b64decode(b64['iv'])
    ct = base64.b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    plaintext_data = pt.decode('utf-8')
    logger.debug(f"Decrypted data: {plaintext_data}")
    return plaintext_data

@app.route('/create_company', methods=['POST'])
def create_company():
    logger.info("Received request to create company")
    data = request.json
    logger.debug(f"Request data: {data}")
    company_id = data['company_id']
    
    logger.info(f"Building transaction to create company: company_id={company_id}")
    nonce = w3.eth.get_transaction_count(account.address)
    logger.debug(f"Nonce: {nonce}")
    tx = contract.functions.createCompany(company_id).build_transaction({
        'chainId': 43114,
        'gas': 800000,
        'gasPrice': w3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    logger.debug(f"Transaction: {tx}")
    
    logger.info("Signing transaction")
    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    logger.debug(f"Signed transaction: {signed_tx}")
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    logger.debug(f"Transaction hash: {tx_hash.hex()}")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    logger.info(f"Company created with transaction hash: {tx_receipt.transactionHash.hex()}")
    
    return jsonify({'transaction_hash': tx_receipt.transactionHash.hex()})

@app.route('/add_data', methods=['POST'])
def add_data():
    logger.info("Received request to add data")
    data = request.json
    logger.debug(f"Request data: {data}")
    
    try:
        company_id = data['company_id']
        data_id = data['data_id']
        plaintext_data = json.dumps(data['data'])  # Convertir data a una cadena JSON
        detalle = data.get('detalle', '')  # Campo opcional
        logger.debug(f"company_id={company_id}, data_id={data_id}, detalle={detalle}")
        
        encrypted_data = encrypt_data(data_id, plaintext_data)
        
        logger.info("Building transaction to add data")
        nonce = w3.eth.get_transaction_count(account.address)
        logger.debug(f"Nonce: {nonce}")
        tx = contract.functions.addData(company_id, data_id, encrypted_data, detalle).build_transaction({
            'chainId': 43114,
            'gas': 800000,
            'gasPrice': w3.to_wei('50', 'gwei'),
            'nonce': nonce,
        })
        logger.debug(f"Transaction: {tx}")
        
        logger.info("Signing transaction")
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        logger.debug(f"Signed transaction: {signed_tx}")
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        logger.debug(f"Transaction hash: {tx_hash.hex()}")
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(f"Data added with transaction hash: {tx_receipt.transactionHash.hex()}")
        
        return jsonify({'transaction_hash': tx_receipt.transactionHash.hex()})
    except Exception as e:
        logger.error(f"Error adding data: {str(e)}")
        return jsonify({'error': 'An error occurred while adding data'} + str(e)), 500


@app.route('/get_data', methods=['GET'])
def get_data():
    logger.info("Received request to get data")
    company_id = request.args.get('company_id')
    data_id = request.args.get('data_id')
    
    if not company_id or not data_id:
        logger.error("Missing company_id or data_id in request")
        return jsonify({'error': 'Missing company_id or data_id in request'}), 400
    
    logger.debug(f"Request args: company_id={company_id}, data_id={data_id}")
    try:
        encrypted_data, detalle = contract.functions.getData(company_id, data_id).call({'from': account.address})
        logger.debug(f"Encrypted data: {encrypted_data}, Detalle: {detalle}")
        
        if not encrypted_data:
            logger.info("No data found for the provided company_id and data_id")
            return jsonify({'error': 'Record not found'}), 404
        
        plaintext_data = decrypt_data(data_id, encrypted_data)
        logger.info("Data retrieved successfully")
        
        # Convertir la cadena JSON a un objeto Python
        data_json = json.loads(plaintext_data)
        
        return jsonify({'data': data_json, 'detalle': detalle})
    except Exception as e:
        logger.error(f"Error retrieving data: {str(e)}")
        
        # Parse the exception to check for blockchain error messages
        error_message = str(e)
        if 'execution reverted' in error_message:
            if 'Data does not exist' in error_message:
                return jsonify({'error': 'Data does not exist'}), 404
            if 'Company does not exist' in error_message:
                return jsonify({'error': 'Company does not exist'}), 404
        
        return jsonify({'error': 'An error occurred while retrieving data' + str(e)}), 500



if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8098)
