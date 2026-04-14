#include <openssl/des.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <random>

using namespace std;

// make a random 16 bit salt
unsigned short make_salt() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<unsigned short> dist(0, 65535);
    return dist(gen);
}

// turn bytes into hex text
string bytes_to_hex(unsigned char *data, int len) {
    stringstream ss;
    ss << hex << setfill('0');

    for (int i = 0; i < len; i++) {
        ss << setw(2) << (int)data[i];
    }

    return ss.str();
}

// turn salt into 4 hex digits
string salt_to_hex(unsigned short salt) {
    stringstream ss;
    ss << hex << setw(4) << setfill('0') << salt;
    return ss.str();
}

// fill an 8 byte des key from the password
void make_key_from_password(const string& password, DES_cblock &key) {
    for (int i = 0; i < 8; i++) {
        if (i < (int)password.size()) {
            key[i] = (static_cast<unsigned char>(password[i]) << 1) & 0xfe;
        } else {
            key[i] = 0;
        }
    }

    // des wants odd parity
    DES_set_odd_parity(&key);
}

// this does the 25 rounds of des
string encrypt_password(const string& password, unsigned short salt) {
    DES_cblock key;
    make_key_from_password(password, key);

    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    DES_cblock block = {0};
    DES_cblock out;

    unsigned short current_salt = salt;

    for (int round = 0; round < 25; round++) {
        // mix the salt into the block before each round
        block[0] ^= current_salt & 0xff;
        block[1] ^= (current_salt >> 8) & 0xff;
        block[6] ^= (current_salt & 0xff) ^ 0xa5;
        block[7] ^= ((current_salt >> 8) & 0xff) ^ 0x5a;

        DES_ecb_encrypt(&block, &out, &schedule, DES_ENCRYPT);

        // copy output back into block for next round
        for (int i = 0; i < 8; i++) {
            block[i] = out[i];
        }

        // change salt a little every round
        current_salt = ((current_salt << 1) | (current_salt >> 15)) ^ (0x9e37 + round * 0x31);
    }

    return salt_to_hex(salt) + "$" + bytes_to_hex(reinterpret_cast<unsigned char*>(block), 8);
}

// check if password matches stored encrypted password
bool check_password(const string& password, const string& saved_hash) {
    int pos = saved_hash.find('$');

    if (pos == string::npos) {
        return false;
    }

    string salt_part = saved_hash.substr(0, pos);
    unsigned short salt = (unsigned short)stoul(salt_part, nullptr, 16);

    string new_hash = encrypt_password(password, salt);

    return new_hash == saved_hash;
}

int main() {
    vector<string> words = {
        "falcon",
        "orange7",
        "delta99",
        "unixlab",
        "cipher1",
        "student",
        "winter22",
        "kernel",
        "secureme",
        "pass1234"
    };

    vector<string> saved_list;

    cout << "10 encrypted passwords using des with 25 rounds and 16 bit salt\n\n";

    for (string word : words) {
        unsigned short salt = make_salt();
        string encrypted = encrypt_password(word, salt);
        saved_list.push_back(encrypted);

        cout << left << setw(12) << word << " -> " << encrypted << endl;
    }

    cout << "\npassword check test\n";
    cout << "correct password for first one: ";

    if (check_password(words[0], saved_list[0])) {
        cout << "valid\n";
    } else {
        cout << "invalid\n";
    }

    cout << "wrong password for first one: ";

    if (check_password("wrongpass", saved_list[0])) {
        cout << "valid\n";
    } else {
        cout << "invalid\n";
    }

    return 0;
}