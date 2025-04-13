# clientStorageSystem (Client) for SecureVault
The clientStorageSystem is the client-side component of SecureVault, a
secure file storage solution developed for the COMP3334 project. It
provides a console-based interface for users to interact with the Secure
Storage System (server), enabling secure file management operations like
registration, file uploads, sharing, and password resets with multi-factor
authentication (MFA). The client ensures all sensitive operations, such as
encryption, are performed locally, maintaining data confidentiality.
## Features
The clientStorageSystem offers the following functionalities:
- Registers users with the server, hashing passwords with HmacSHA256 before
transmission.
- Authenticates users securely, using constant-time hash comparison to
prevent timing attacks.
- Encrypts files client-side using AES-256 in CBC mode, with keys derived
from passwords via PBKDF2.
- Facilitates file operations (upload, download, rename, delete, share)
through server API calls.
- Supports MFA for password resets by collecting OTPs sent to users’ emails
and submitting them to the server.
- Displays audit logs for admin users via the server’s admin endpoint.
## Project Architecture
The clientStorageSystem is a Java application with the following
components:
- **Main Interface**: `ClientView.java` provides a console-based menu for
user interaction, using `java.util.Scanner` for input.
- **API Communication**: Uses `java.net.http.HttpClient` to interact with
the server’s REST APIs, with `java.net.URLEncoder` for input sanitization.
- **Cryptography**: Implements HmacSHA256 for password hashing, PBKDF2 for
key derivation, and AES-256 for file encryption, with SecureRandom for
randomness.
The client communicates with the server over HTTP (assumed TLS in
production), sending requests to endpoints like `/api/user/register` and
`/api/file/upload`.
## Prerequisites
To run the clientStorageSystem, ensure you have:
- Java 17 or later ([download](https://www.java.com/en/download/))
- Maven 3.8.x ([download](https://maven.apache.org/download.cgi))
- Git (optional, for cloning)
- A running instance of the Secure Storage System (server)
## Setup Instructions
First, ensure Java and Maven are installed as outlined in the
prerequisites. Confirm that the Secure Storage System (server) is running
on `localhost:8080` (or the configured host/port). Download the client
repository into the same directory as the server for consistency:
## Running the client
Run the client in bash using maven with the following command:
```
mvn clean compile exec:java
```