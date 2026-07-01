# License Verification System (Client/Vendor)

A simple RSA-based license generation and verification project using Python and Docker.  
The project has two separate components:

- **Vendor**: Generates signed licenses using a private key
- **Client**: Generates a machine fingerprint (hash) and verifies entered license using vendor public key

---

## Project Structure
```bash
.
├── Client
│   ├── app
│   │   ├── license_manager.py
│   │   ├── machine.py
│   │   ├── main.py
│   │   ├── public_key.pem
│   │   └── __pycache__
│   ├── Dockerfile
│   └── requirements.txt
├── docker-compose.yml
└── Vendor
├── app
│   └── license_generator.py
├── Dockerfile
└── keys
└── private_key.pem
```

---

## How It Works

1. Client app generates a unique machine hash/fingerprint.
2. Client waits for a license input from user.
3. Vendor app receives machine hash and signs it with private key.
4. Vendor outputs license string.
5. User copies the license and pastes it into client.
6. Client verifies license using public key.
7. License is accepted or rejected.

---

## Requirements

- Python 3.12+
- `cryptography`
- `psutil`
- Docker / Docker Compose (optional, for containerized run)

---

## Local Run (Without Docker)

> Recommended when testing interactively.

### 1) Create and activate virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies (Client side)

```bash
pip install -r Client/requirements.txt
```

> If needed for vendor local run:

```bash
pip install cryptography
```

### 3) Run client

```bash
python Client/app/main.py
```

- Client prints a machine hash.
- Keep this terminal open (it waits for license input).

### 4) Run vendor generator in another terminal

```bash
python Vendor/app/license_generator.py
```

- Paste machine hash from client terminal.
- Vendor returns generated license.

### 5) Paste license back into client terminal

- Client validates and prints result: **valid** or **invalid**.

---

## Docker Run

### Build and run services

```bash
docker compose up --build
```

Because both services are interactive (`stdin_open: true`, `tty: true`), you can attach to each container and run scripts manually if needed.

---

## Dockerfiles

### Client Dockerfile
- Uses `python:3.12-slim`
- Installs dependencies from `requirements.txt`
- Runs `main.py`

### Vendor Dockerfile
- Uses `python:3.12-slim`
- Installs `cryptography`
- Runs `license_generator.py`

---

## Security Notes

- `Vendor/keys/private_key.pem` is sensitive and should never be exposed publicly.
- Public key can be distributed with the client (`Client/app/public_key.pem`).
- Current `.gitignore` excludes private `.pem` files in `Vendor/keys`.

---

## .gitignore
```
gitignore
Vendor/keys/*.pem
__pycache__/
*.pyc
```
---

## Troubleshooting

- If dependency install fails, upgrade pip:
  
```bash
  python -m pip install --upgrade pip
```
