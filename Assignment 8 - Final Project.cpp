#include <iostream>
#include <string>
#include <curl/curl.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    size_t oldLength = s->size();
    try {
        s->resize(oldLength + newLength);
    } catch (std::bad_alloc &e) {
        return 0;
    }
    std::copy((char*)contents, (char*)contents + newLength, s->begin() + oldLength);
    return size * nmemb;
}

std::string fetchText(const std::string& url) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint32_t initial_hash_values[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

uint32_t sig0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint32_t sig1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint32_t theta0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint32_t theta1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

std::vector<uint8_t> sha256(const std::string& data) {
    std::vector<uint8_t> hash(32);
    std::vector<uint8_t> padded_data = std::vector<uint8_t>(data.begin(), data.end());

    size_t bit_len = padded_data.size() * 8;
    padded_data.push_back(0x80);
    while (padded_data.size() % 64 != 56) {
        padded_data.push_back(0);
    }
    for (int i = 7; i >= 0; --i) {
        padded_data.push_back((bit_len >> (i * 8)) & 0xff);
    }

    uint32_t hash_values[8];
    memcpy(hash_values, initial_hash_values, sizeof(hash_values));

    for (size_t chunk = 0; chunk < padded_data.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (padded_data[chunk + i * 4 + 0] << 24) |
                   (padded_data[chunk + i * 4 + 1] << 16) |
                   (padded_data[chunk + i * 4 + 2] << 8) |
                   (padded_data[chunk + i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = hash_values[0];
        uint32_t b = hash_values[1];
        uint32_t c = hash_values[2];
        uint32_t d = hash_values[3];
        uint32_t e = hash_values[4];
        uint32_t f = hash_values[5];
        uint32_t g = hash_values[6];
        uint32_t h = hash_values[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + sig1(e) + choose(e, f, g) + k[i] + w[i];
            uint32_t T2 = sig0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        hash_values[0] += a;
        hash_values[1] += b;
        hash_values[2] += c;
        hash_values[3] += d;
        hash_values[4] += e;
        hash_values[5] += f;
        hash_values[6] += g;
        hash_values[7] += h;
    }

    for (int i = 0; i < 8; ++i) {
        hash[i * 4 + 0] = (hash_values[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (hash_values[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (hash_values[i] >> 8) & 0xff;
        hash[i * 4 + 3] = (hash_values[i]) & 0xff;
    }

    return hash;
}

std::string to_hex_string(const std::vector<uint8_t>& hash) {
    std::stringstream ss;
    for (uint8_t byte : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

int main() {
    std::string url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";
    std::string text = fetchText(url);

    std::vector<uint8_t> hash = sha256(text);
    std::string hash_hex = to_hex_string(hash);

    std::cout << "SHA-256 Hash of the Book of Mark: " << hash_hex << std::endl;
    return 0;
}
