# OAuth 2.0 Authorization Server

**Author:** Madeline Moldrem  
**Version:** 1.0.0

## Overview

This project implements an OAuth 2.0 authorization server using **Express**, **Passport**, and **Sequelize**. It is designed to handle user authentication, consent management, and token issuance within a polyglot microservices architecture. The server issues JSON Web Tokens (JWTs) using an asymmetric key pair with the ES256 algorithm and supports both access and refresh tokens.

**Key Features:**
- **User Authentication:** Secure registration and login with CSRF protection and password hashing.
- **OAuth Flow with Consent Persistence:** Users grant consent for a client once; subsequent logins bypass the consent screen while still issuing fresh tokens.
- **JWT Issuance:** Tokens are signed using ES256 with an ECC key pair. The private key remains secure on the server, while the public key is shared with resource servers or an API Gateway.
- **API Gateway Integration:** Centralizes token validation and routing to protect resource servers.
- **Brute-Force Protection:** Implements rate limiting (and optionally account locking) to mitigate automated attacks.
- **Scalability:** A mostly stateless design (apart from session management) enables horizontal scaling to handle high loads.

## Architecture

### Components

- **Authorization Server:**
    - **Responsibilities:**
        - User registration and login.
        - Handling the OAuth flow (consent, authorization code issuance, token exchange).
        - Issuing JWT access tokens and refresh tokens.
        - Storing tokens as HTTP‑only cookies.
    - **Key Endpoints:**
        - `/register` – User registration.
        - `/login` – User login.
        - `/authorize` – Consent screen (or automatic approval if consent is already stored).
        - `/callback` – Token exchange endpoint that generates and issues JWTs.
        - `/logout` – Session termination and token revocation.

- **API Gateway:**
    - Serves as the single entry point for all client requests.
    - Validates JWT tokens before routing requests to resource servers.
    - Enforces centralized security policies.

- **Resource Servers (External):**
    - Implemented in other languages/frameworks (e.g., Flask, Spring Boot).
    - Rely on the JWT (validated by the API Gateway or via shared middleware) to protect endpoints.

### Consent Persistence (Hybrid Approach)

- **Initial Consent:**  
  When a user first approves an OAuth request, the server stores their consent in the `UserClientConsent` model for that client.
- **Subsequent Logins:**  
  The server checks for existing consent:
    - **If consent exists:** The consent screen is bypassed, and an authorization code is generated immediately.
    - **If no consent exists:** The consent page is rendered for the user to approve or deny access.
- **Redirection:**  
  The server uses the client’s registered `redirect_uri` (or a dedicated `landing_page`) to send the user back after token exchange.

### JWT Signing & Verification

- **Algorithm:** ES256 (Elliptic Curve Digital Signature Algorithm using the P-256 curve and SHA-256).
- **Key Management:**
    - **Private Key:** Used to sign tokens; must remain secure on the authorization server.
    - **Public Key:** Distributed to resource servers or the API Gateway to verify tokens.
    - **Keys are loaded from files:** Their file paths are stored in environment variables.

## Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/oauth-server.git
cd oauth-server
npm install
npm run dev
npm start
```


### Configure Your Environment

```aidl
# General settings
NODE_ENV=dev
PORT=3001
SESSION_SECRET=your_session_secret
CLIENT_ID=your_client_id
OAUTH_URI=http://your-auth-server-domain/oauth
DATABASE_URL=postgres://<db_username>:<db_password>@<db_host>:<db_port>/<db_name>

# JWT key file paths (store your key files in a 'keys' folder)
JWT_PRIVATE_KEY_PATH=./keys/your_ec_private_key.pem
JWT_PUBLIC_KEY_PATH=./keys/your_ec_public_key.pem

# Database specific values
DB_USERNAME=your_db_username
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
DB_HOST=your_db_host
DIALECT=postgres

```