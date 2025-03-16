#include "signature.hpp"

// Exemple de chargement de signatures par défaut
void loadDefaultSignatures(std::unordered_set<std::string>& db) {
    db.insert("malicious_pattern_1");
    db.insert("malicious_pattern_2");
    // etc.
    db.insert("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"); // Signature SYN Flood
    // ...
}
