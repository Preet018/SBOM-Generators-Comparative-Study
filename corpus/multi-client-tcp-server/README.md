<p align="left">
  <img src="https://img.shields.io/badge/Language-C11-blue?style=flat-square&logo=c&logoColor=white" alt="C11">
  <img src="https://img.shields.io/badge/Networking-TCP%20Sockets-00599C?style=flat-square&logo=gnubash&logoColor=white" alt="TCP Sockets">
  <img src="https://img.shields.io/badge/Concurrency-POSIX%20Threads-232F3E?style=flat-square&logo=linux&logoColor=white" alt="POSIX Threads">
  <img src="https://img.shields.io/badge/IPC-Shared%20Memory%20%26%20Semaphores-orange?style=flat-square&logo=linux&logoColor=white" alt="System V IPC">
  <img src="https://img.shields.io/badge/Locking-fcntl%20Advisory%20Locks-red?style=flat-square&logo=linux&logoColor=white" alt="fcntl Locking">
  <img src="https://img.shields.io/badge/Build-GNU%20Make%20%7C%20CMake-046A38?style=flat-square&logo=gnu&logoColor=white" alt="Build">
</p>

---

# Multi-Client Banking Management System & TCP Server

## Project Overview

This project implements a robust, concurrent, multi-client **Banking Management System** in **C** using a client-server architecture over **TCP Sockets**. It is designed to simulate a real-world core banking system where multiple users across different roles (**Customers**, **Bank Employees**, **Managers**, and **System Administrators**) can securely and simultaneously interact with their accounts.

The project demonstrates low-level systems programming concepts including **multithreading (`pthread`)**, **Inter-Process Communication (IPC)** via **System V Shared Memory and Semaphores**, **Advisory File Record Locking (`fcntl`)** to prevent race conditions during transactions, and **I/O Multiplexing (`poll()`)** for non-blocking client interaction.

---

## Core System Architecture & Workflow

The system is structured across the following architectural stages:

### 1. TCP Socket Networking & Multiplexing
*   **TCP Server:** Listens for incoming connections on port `8080` using BSD sockets (`AF_INET`, `SOCK_STREAM`).
*   **Client I/O Multiplexing:** The client employs the `poll()` system call to simultaneously monitor `stdin` and the TCP socket file descriptor without blocking user input.

### 2. Multi-Threaded Client Handling
*   **Thread-Per-Client Model:** For each incoming client connection, the server creates an independent, detached POSIX thread (`pthread_create`, `pthread_detach`).
*   **Thread Lifecycle:** Threads handle complete user authentication, session tracking, role menus, and safe connection termination.

### 3. IPC Session Management & Concurrency Control
*   **Shared Memory (`shmat`, `shmget`):** Maintains a shared active session table across processes to track logged-in users in real time.
*   **Binary Semaphore (`semop`, `semctl`):** Synchronizes concurrent access to the session table to strictly enforce single-login policies (preventing concurrent logins of the same user).

### 4. Critical Section & File Record Locking
*   **Advisory File Locking (`fcntl`):** Read and write operations on CSV files are protected using `F_WRLCK` and `F_UNLCK`.
*   **Data Integrity:** Guarantees atomic balance deductions, credit operations, and transfers, eliminating dirty reads, write conflicts, and race conditions.

### 5. Multi-Role Banking Business Logic
*   **Customer Operations:** View balance, deposit, withdraw, fund transfer, loan application & tracking, transaction passbook history, and feedback.
*   **Employee Operations:** Customer registration, profile modification, loan processing/approval (auto-credit on approval), and customer passbook viewing.
*   **Manager Operations:** Customer account activation/deactivation, loan assignment to employees, and customer feedback review.
*   **Admin Operations:** Employee profile management, user role assignments, and full system configuration.

---

## Technical Stack

*   **Languages:** C (C11 / GNU11 Standard)
*   **Networking:** Berkeley TCP Sockets (`AF_INET`, `SOCK_STREAM`)
*   **Concurrency:** POSIX Threads (`pthread`)
*   **IPC & Synchronization:** System V Shared Memory (`shmget`, `shmat`), System V Semaphores (`semget`, `semop`, `semctl`)
*   **File Locking & Safety:** Advisory Record Locking (`fcntl`, `F_WRLCK`, `F_UNLCK`)
*   **I/O Multiplexing:** `poll()` System Call
*   **Build Tools:** GNU Make, CMake (3.10+)
*   **Target Environment:** Linux / POSIX / macOS
*   **Database:** Structured CSV flat files for persistent storage

---

## Project Structure

```bash
├── admin.c                 # Administrator functionality and employee management
├── admin.h                 # Admin module header
├── auth.c                  # Role-based credential verification and authentication
├── auth.h                  # Authentication module header
├── customer.c              # Customer operations (balance, deposit, withdraw, transfer, loans)
├── customer.h              # Customer module header
├── employee.c              # Employee operations (customer modification, loan processing)
├── employee.h              # Employee module header
├── manager.c               # Manager operations (account activation, loan assignment)
├── manager.h               # Manager module header
├── session_manager.c       # IPC Shared Memory & Semaphore session tracking
├── session_manager.h       # Session manager module header
├── utils.c                 # Networking utilities, file record locking, string formatting
├── utils.h                 # Utility definitions
├── common.h                # Global structs, role IDs, and server configurations
├── server.c                # TCP Server socket initialization & thread dispatcher
├── server.h                # Server module header
├── client.c                # TCP Client terminal interface with poll() multiplexing
├── client.h                # Client module header
├── data/                   # Persistent CSV Database Directory
│   ├── customers.csv       # Customer account records and balances
│   ├── employees.csv       # Employee authentication records
│   ├── managers.csv        # Manager authentication records
│   ├── admins.csv          # Admin authentication records
│   ├── transactions.csv    # Financial transaction history and logs
│   ├── loans.csv           # Loan applications, status, and assignment data
│   └── feedback.csv        # Customer feedback records
├── Makefile                # Automated compilation and execution commands
└── CMakeLists.txt          # CMake build configuration
```

---

## Build & Execution Instructions

### 1. Initialize Sample Database
Create the `data/` directory and populate initial CSV records:
```bash
make setup
```

### 2. Compile Server and Client
Build both the server and client binaries using GNU Make:
```bash
make
```

### 3. Run Server
Start the multi-threaded TCP server:
```bash
make run-server
# OR
./server
```

### 4. Run Client
In one or more separate terminal windows:
```bash
make run-client
# OR
./client
```

### 5. Clean Build Artifacts
Remove compiled executables and temporary object files:
```bash
make clean
```
