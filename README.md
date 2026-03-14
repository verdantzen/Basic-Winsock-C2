# Basic-Winsock-C2

## Overview
Basic-Winsock-C2 is a lightweight Command and Control (C2) application written in C++ for Windows. It utilizes the Windows Sockets API (Winsock2) for raw TCP communication between a server (listener) and a client (payload). The project serves as an educational demonstration of remote operations and data exfiltration techniques, featuring custom AES-encrypted file transfers, remote command execution, screen capturing capabilities, and basic persistence mechanisms.

## Features
- **Remote Command Execution**: Send commands from the server to be executed on the client machine.
- **File System Interaction**:
  - `mkfile`: Create new empty files on the remote system.
  - `delete`: Delete files from the remote system.
  - `stealfile`: Exfiltrate files from the client to the server with AES-ECB encryption utilizing Windows Cryptography API: Next Generation (CNG).
  - Directory Listing: Run `stealfile` without arguments to list all files and directories in the client's current working directory.
- **Screen Capture**: Use the `screencap` command to capture the client's screen using GDI+ and transfer it as a JPG back to the server.
- **Stealth and Persistence**:
  - The client executable runs as a hidden GUI application (no console window).
  - Silently adds itself to the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` registry key under "Audio Device Helper" for persistence across reboots.

## Principle of Operation
The project operates in a classic Client-Server architecture over TCP/IP:
1. **Server (`winSockServer`)**: Binds to a local port (default is TCP `25566`) and listens for incoming connections. Once a client connects, it spawns a background thread to handle incoming data asynchronously while keeping the main thread available for a command-line interface. 
2. **Client (`winSockClient`)**: Designed to be the payload executed on the target machine. It resolves the server address and attempts to establish a connection. Upon a successful connection, it waits infinitely for incoming strings and dispatches them to a command parser (`ExecuteCommand()`).
3. **Data Encryption (`BCrypt`)**: All exfiltrated files transferred via `stealfile` are chunked into 8KB blocks. To maintain confidentiality on the wire, each block is encrypted individually using the Windows CNG framework (`bcrypt.lib`) with AES in ECB mode. A 256-bit symmetric key is dynamically generated at runtime using SHA-256 PBKDF2 with a hardcoded secret. The server decrypts these chunks sequentially to reconstruct the stolen file completely.

## Project Structure
```text
winSock/
├── CMakeLists.txt              # Top-level CMake project configuration
├── winSockServer/
│   ├── CMakeLists.txt          # Server-specific CMake build script
│   └── winSockServer.cpp       # Listener logic, UI prompt, decryption, file saving
└── winSockClient/
    ├── CMakeLists.txt          # Client-specific CMake build script
    └── winSockClient.cpp       # Payload logic, command parsing, screen capture, encryption
```

## Requirements
- **Operating System**: Windows 10 or later (for CNG algorithm handles)
- **Compiler**: Visual Studio 2019/2022 / MSVC (C++)
- **Build System**: CMake 3.10+
- **Libraries (Linked against Windows SDK)**:
  - `ws2_32.lib` (Winsock2)
  - `gdiplus.lib` (GDI+ for Screen Capture)
  - `bcrypt.lib` (CNG Cryptography API)

## How to Build
To build the project from scratch, use CMake. Ensure you are running within a Developer Command Prompt for Visual Studio if compiling on Windows to ensure MSVC is in your path.

```cmd
mkdir build
cd build
cmake .. -A Win32
cmake --build . --config Release
```

## Usage
1. Configure the `PORT` and server IP macros in the source files (if deploying remotely). By default, the project test locally on port `25566`.
2. **Start the Server**: Run `winSockServer.exe`. The server will initialize and await a callback on the specified port.
3. **Deploy the Client**: Run `winSockClient.exe` on your target Windows environment. 
4. Upon successful connection, the server console will log the event and display a `COMMAND>` prompt.

**Available Commands:**
- `mkfile <filepath>`: Attempt to create an empty text file at the specified absolute or relative path.
- `delete <filepath>`: Attempt to delete a file.
- `stealfile`: Retrieve the directory listing of the client process context.
- `stealfile <filepath>`: Securely download a target file back to the root of the server executable in chunks.
- `screencap`: Capture the entire desktop environment as a `.jpeg` and send it sequentially back to the server.
- `exit`: Shutdown the server locally.