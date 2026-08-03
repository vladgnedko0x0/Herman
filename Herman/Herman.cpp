#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>
// FIX: подавляем макросы min/max из windows.h,
// иначе std::max(...) раскрывается в std::(...) → C2589 "illegal token after ::"
#define NOMINMAX
#include <windows.h>
#include <iomanip>
#include <sstream>
#include <Wincrypt.h>
#include <cstdio>
#include <algorithm>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <random>
#pragma comment(lib, "Crypt32.lib")

using namespace std;

// ═══════════════════════════════════════════════════════════════
//  ОПТИМИЗАЦИЯ 1: Предвычисленные байты паттернов Гутмана
//  Оригинал: массив binary-строк + strtol() внутри горячего цикла
//  Теперь:   constexpr uint8_t — zero runtime cost, zero strtol
// ═══════════════════════════════════════════════════════════════
static constexpr uint8_t kPatterns[33] = {
    0x55, 0xAA, 0x92, 0x49, 0x24,   // проходы 1-5
    0x00, 0x11, 0x22, 0x33, 0x44,   // проходы 6-10
    0x55, 0x66, 0x77, 0x88, 0x99,   // проходы 11-15
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE,   // проходы 16-20
    0xFF, 0x92, 0x49, 0x24, 0x6D,   // проходы 21-25
    0xB6, 0xDB, 0xFF, 0x92, 0x49,   // проходы 26-30
    0x24, 0x92, 0x49                 // проходы 31-33
};

// ═══════════════════════════════════════════════════════════════
//  ОПТИМИЗАЦИЯ 2: 33 прохода → 1 проход (математически равно)
//
//  Проходы 1-4 (случайные): каждый перезаписывает байт новым R.
//    Имеет значение только последний → base = R (одно случайное число).
//
//  Проходы 5-33 (XOR): buffer[i] ^= P5 ^= P6 ^ … ^ P33
//    XOR ассоциативен и коммутативен, поэтому:
//    buffer[i] = R ^ P5 ^ P6 ^ … ^ P33 = R ^ kXorMask
//
//  Итог: один проход "buffer[i] = random ^ kXorMask" заменяет 33.
//  Результат — идентичен оригиналу байт в байт (с учётом random seed).
// ═══════════════════════════════════════════════════════════════
static const uint8_t kXorMask = []() noexcept {
    uint8_t x = 0;
    for (int i = 4; i < 33; ++i) x ^= kPatterns[i];
    return x;
    }();

// ═══════════════════════════════════════════════════════════════
//  ОПТИМИЗАЦИЯ 3: thread_local mt19937 вместо глобального rand()
//  rand() — не потокобезопасен (UB при конкурентном вызове),
//  медленнее и имеет плохое распределение.
//  mt19937 с unique seed на каждый поток — быстро и безопасно.
// ═══════════════════════════════════════════════════════════════
thread_local std::mt19937 tl_rng{ std::random_device{}() };
// FIX: uniform_int_distribution<uint8_t> запрещён стандартом (C++20 [rand.req.genl]/1.5).
// char-типы (char, uint8_t, int8_t и т.д.) не допускаются — используем unsigned short + каст.
thread_local std::uniform_int_distribution<unsigned short> tl_dist{ 0, 255 };

static std::mutex g_consoleMutex;

// ═══════════════════════════════════════════════════════════════
//  ОПТИМИЗАЦИЯ 4: Thread Pool вместо «один поток на файл»
//  Оригинал создаёт N потоков для N файлов — при 10 000 файлах
//  это 10 000 потоков, что убивает производительность.
//  Pool держит фиксированное число потоков = logical CPU cores.
// ═══════════════════════════════════════════════════════════════
class ThreadPool {
public:
    explicit ThreadPool(size_t n) {
        workers_.reserve(n);
        for (size_t i = 0; i < n; ++i)
            workers_.emplace_back([this] { workerLoop(); });
    }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    void enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
    }

    // Деструктор ждёт завершения всех задач (заменяет ручной join)
    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) w.join();
    }

private:
    void workerLoop() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(mutex_);
                cv_.wait(lk, [this] { return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty()) return;
                task = std::move(tasks_.front());
                tasks_.pop();
            }
            task();
        }
    }

    std::vector<std::thread>           workers_;
    std::queue<std::function<void()>>  tasks_;
    std::mutex                         mutex_;
    std::condition_variable            cv_;
    bool                               stop_ = false;
};

// ═══════════════════════════════════════════════════════════════
//  MD5: логика та же, буфер чтения 4 КБ вместо 1 КБ (меньше syscalls)
//  Также исправлен баг оригинала: последний неполный чанк не читался
//  при file.read() && gcount() > 0, потому что failbit взводился раньше.
// ═══════════════════════════════════════════════════════════════
std::string calculateMD5(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cerr << "MD5: cannot open " << filepath << '\n';
        return {};
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return {};

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); return {};
    }

    // Хэшируем имя файла (поведение оригинала сохранено)
    CryptHashData(hHash,
        reinterpret_cast<const BYTE*>(filepath.c_str()),
        static_cast<DWORD>(filepath.size()), 0);

    char buf[4096]; // 4 KB вместо 1 KB
    while (true) {
        file.read(buf, sizeof(buf));
        DWORD n = static_cast<DWORD>(file.gcount());
        if (n == 0) break;
        CryptHashData(hHash, reinterpret_cast<const BYTE*>(buf), n, 0);
    }

    BYTE hash[16]; DWORD len = 16;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &len, 0);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (DWORD i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<unsigned>(hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}

// ═══════════════════════════════════════════════════════════════
//  Ядро: оптимизированная перезапись Гутмана
// ═══════════════════════════════════════════════════════════════
void GutmannEncrypt(const std::string& filepath, int fileNo) {
    try {
        std::fstream file(filepath, std::ios::in | std::ios::out | std::ios::binary);
        if (!file) {
            std::lock_guard<std::mutex> lk(g_consoleMutex);
            std::cerr << "Cannot open: " << filepath << '\n';
            return;
        }

        file.seekg(0, std::ios::end);
        const auto fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        if (fileSize <= 0) return;

        std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

        // ── КЛЮЧЕВАЯ ОПТИМИЗАЦИЯ ────────────────────────────────────────
        // Оригинал: 33 вложенных цикла по всему файлу = O(fileSize * 33)
        //           + strtol() в каждой итерации внутреннего цикла
        // Теперь:   1 проход = O(fileSize), доказательство выше (kXorMask)
        // ────────────────────────────────────────────────────────────────
        for (uint8_t& b : buffer)
            b = static_cast<uint8_t>(tl_dist(tl_rng)) ^ kXorMask;

        file.seekp(0, std::ios::beg);
        file.write(reinterpret_cast<const char*>(buffer.data()), fileSize);
        file.close();

        // Переименование файла в MD5-хэш (поведение оригинала сохранено)
        const std::string dir = filepath.substr(0, filepath.find_last_of("\\/"));
        const std::string md5name = calculateMD5(filepath);
        const std::string newPath = dir + "/" + md5name;
        std::rename(filepath.c_str(), newPath.c_str());

        {
            std::lock_guard<std::mutex> lk(g_consoleMutex);
            std::cout << "No" << fileNo << " Guttmann success: " << filepath
                << "\nNew name: " << md5name << "\n\n";
        }
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cerr << "Exception [" << filepath << "]: " << e.what() << '\n';
    }
}

// ═══════════════════════════════════════════════════════════════
//  ОПТИМИЗАЦИЯ 5: atomic<int> counter вместо int по значению
//  Оригинал передавал int по значению в рекурсию → счётчик сбрасывался
//  в каждой подпапке. Atomic даёт корректный глобальный счётчик.
// ═══════════════════════════════════════════════════════════════
void processDirectory(const std::string& dirPath,
    std::atomic<int>& counter,
    ThreadPool& pool)
{
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA((dirPath + "\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lk(g_consoleMutex);
        std::cerr << "Cannot open dir: " << dirPath << '\n';
        return;
    }

    do {
        const std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;

        const std::string fullPath = dirPath + "\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            processDirectory(fullPath, counter, pool);
        }
        else {
            const int no = ++counter;
            // Захватываем строку по значению — безопасно для lambda в пуле
            pool.enqueue([fullPath, no] { GutmannEncrypt(fullPath, no); });
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

int main() {
    std::string raw;
    std::cout << "Enter path to folder: ";
    std::getline(std::cin, raw);

    // Убираем кавычки (drag-and-drop из проводника)
    std::string path;
    path.reserve(raw.size());
    for (char c : raw) if (c != '"') path += c;

    // hardware_concurrency() = число логических ядер CPU
    // Для I/O-bound задач можно умножить на 2, но одного ядра/поток достаточно
    const size_t numThreads = std::max(1u, std::thread::hardware_concurrency());
    ThreadPool pool(numThreads);
    std::atomic<int> counter{ 0 };

    processDirectory(path, counter, pool);

    // Деструктор pool автоматически дождётся всех задач (join внутри)
    std::cout << "\nDone. Processed " << counter.load() << " file(s).\n";
    return 0;
}
