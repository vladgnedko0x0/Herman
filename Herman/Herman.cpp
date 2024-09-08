#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <stdexcept> // For using std::exception and std::cerr
#include <windows.h>
#include <iomanip> // For std::setw and std::setfill
#include <sstream> // For std::stringstream
#include <Wincrypt.h>
#include <cstdio> // For the rename function
#include <algorithm>
#include <thread> // For multithreading
#include <mutex> // For mutexes
#pragma comment(lib, "Crypt32.lib")

using namespace std;

std::mutex console_mutex; // Mutex for synchronizing console output

std::string calculateMD5(const std::string& filepath) {
    const int MD5LEN = 16;
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file." << std::endl;
        return "";
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed." << std::endl;
        return "";
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed." << std::endl;
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Hash the file name
    if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(filepath.c_str()), filepath.length(), 0)) {
        std::cerr << "CryptHashData failed." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    char buffer[1024];
    DWORD bytesRead = 0;
    while (file.read(buffer, sizeof(buffer)) && file.gcount() > 0) {
        bytesRead = file.gcount();
        if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(buffer), bytesRead, 0)) {
            std::cerr << "CryptHashData failed." << std::endl;
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    BYTE hash[MD5LEN];
    DWORD hashLength = MD5LEN;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLength, 0)) {
        std::cerr << "CryptGetHashParam failed." << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (DWORD i = 0; i < hashLength; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return oss.str();
}

void GutmannEncrypt(const string filepath, int countOfFile) {
    try {
        // Open the file for reading and writing
        fstream file(filepath, ios::in | ios::out | ios::binary);
        if (!file) {
            {
                std::lock_guard<std::mutex> lock(console_mutex);
                cerr << "File open error, for file: " << filepath << endl;
            }
            return;
        }

        // Read data from the file into memory
        file.seekg(0, ios::end);
        streamsize fileSize = file.tellg();
        file.seekg(0, ios::beg);

        vector<char> buffer(fileSize);
        file.read(buffer.data(), fileSize);

        // Gutmann method passes
        srand(time(NULL));

        // Passes 1-4: random data
        for (int pass = 1; pass <= 4; ++pass) {
            for (int i = 0; i < fileSize; ++i) {
                buffer[i] = rand() % 256;
            }
        }

        // Passes 5-35
        const string patterns[] = {
            "01010101", "10101010", "10010010", "01001001", "00100100",
            "00000000", "00010001", "00100010", "00110011", "01000100",
            "01010101", "01100110", "01110111", "10001000", "10011001",
            "10101010", "10111011", "11001100", "11011101", "11101110",
            "11111111", "10010010", "01001001", "00100100", "01101101",
            "10110110", "11011011", "11111111", "10010010", "01001001",
            "00100100", "10010010", "01001001"
        };
        for (int pass = 5; pass <= 33; ++pass) {
            for (int i = 0; i < fileSize; ++i) {
                buffer[i] ^= strtol(patterns[pass - 1].c_str(), nullptr, 2);
            }
        }

        // Move the write position to the beginning of the file and overwrite it
        file.seekp(0, ios::beg);
        file.write(buffer.data(), fileSize);

        file.close();
        string filename = filepath.substr(filepath.find_last_of("\\/") + 1);
        // Encrypt the filename using MD5
        string encryptedFilename = calculateMD5(filepath);

        // Rename the file
        string newFilepath = filepath.substr(0, filepath.find_last_of("\\/")) + "/" + encryptedFilename;
        rename(filepath.c_str(), newFilepath.c_str());

        {
            std::lock_guard<std::mutex> lock(console_mutex);
            cout << "No" + to_string(countOfFile) + " Guttman success: " << filepath << endl << "New file name: " << encryptedFilename << endl << endl;
        }
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Exception occurred: " << e.what() << std::endl;
    }
}

void processDirectory(const string& dirPath, int i, vector<thread>& threads) {
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;

    string searchPath = dirPath + "\\*";
    hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            string name = findFileData.cFileName;
            if (name != "." && name != "..") {
                string fullPath = dirPath + "\\" + name;
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    processDirectory(fullPath, i, threads); // Recursively process subdirectories
                }
                else {
                    threads.emplace_back(GutmannEncrypt, fullPath, i); // Create a thread to process the file
                    i++;
                }
            }
        } while (FindNextFileA(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    else {
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            cerr << "Error opening directory: " << dirPath << endl;
        }
    }
}

int main() {
    std::string filepathbuffer;
    std::cout << "Enter path to folder: ";
    std::getline(std::cin, filepathbuffer);
    const string filepath = filepathbuffer; // Full path to the file for encryption
    std::string result;
    for (char c : filepath) {
        if (c != '"') {
            result += c;
        }
    }

    vector<thread> threads;
    processDirectory(result, 1, threads);

    // Wait for all threads to finish
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    return 0;
}
