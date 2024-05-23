## Overview

This project provides a Flask web application that interacts with an Avalanche blockchain to manage multi-company data storage. The application includes functionality for creating companies, adding and retrieving encrypted data, and generating CSRF tokens for secure transactions.

## Features

- **Company Management**: Create new companies on the blockchain.
- **Data Management**: Encrypt and store data, as well as retrieve and decrypt data.
- **CSRF Protection**: Generate and manage CSRF tokens for secure transactions.

## Prerequisites

- Python 3.8 or higher
- Flask
- Web3.py
- PyCryptodome
- Flask-WTF

## Installation

1. **Clone the repository**:
   ```sh
   git clone https://github.com/yourusername/multi-company-data-storage.git
   cd multi-company-data-storage
   ```

2. **Install dependencies**:
   ```sh
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   Create a `.env` file in the root directory with the following content:
   ```env
   PRIVATE_KEY=<your_private_key>
   CONTRACT_ADDRESS=<your_contract_address>
   SECRET_KEY=<your_secret_key>
   ```

## Usage

1. **Run the Flask application**:
   ```sh
   flask run
   ```

2. **Endpoints**:

### `/generate_csrf_token` (POST)

Generate a CSRF token with a specified duration.

**Request Body**:
```json
{
  "duration_hours": 24
}
```

**Response**:
```json
{
  "csrf_token": "<token>",
  "duration_hours": 24
}
```

### `/create_company` (POST)

Create a new company on the blockchain.

**Request Body**:
```json
{
  "company_id": "CompanyID"
}
```

**Response**:
```json
{
  "transaction_hash": "<transaction_hash>"
}
```

### `/add_data` (POST)

Add encrypted data for a company.

**Request Body**:
```json
{
  "company_id": "CompanyID",
  "data_id": "DataID",
  "data": {
    "key1": "value1",
    "key2": "value2"
  },
  "detalle": "optional detail"
}
```

**Response**:
```json
{
  "transaction_hash": "<transaction_hash>"
}
```

### `/get_data` (GET)

Retrieve and decrypt data for a company.

**Request Parameters**:

`http://127.0.0.1:8098/get_data?company_id=value&data_id=value`

- `company_id`: ID of the company
- `data_id`: ID of the data

**Response**:
```json
{
  "data": {
    "key1": "value1",
    "key2": "value2"
  },
  "detalle": "optional detail"
}
```

## Docker

To run the application using Docker, ensure you have Docker installed and follow these steps:

1. **Build the Docker image**:
   ```sh
   docker-compose build
   ```

2. **Run the Docker container**:
   ```sh
   docker-compose up
   ```

## Logging

Logging is configured to output debug information. This can be adjusted in the `logging.basicConfig` configuration.

## Security

- **CSRF Protection**: Enabled using Flask-WTF. The CSRF token must be included in the headers of POST requests.
- **Data Encryption**: Data is encrypted using AES before being stored on the blockchain.
