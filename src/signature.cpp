#include "signature.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <regex>

// Fonction helper pour supprimer les espaces en début et fin d'une chaîne.
static inline std::string trim(const std::string &s) {
    auto start = s.begin();
    while (start != s.end() && std::isspace(*start))
        start++;
    auto end = s.end();
    do {
        end--;
    } while (std::distance(start, end) > 0 && std::isspace(*end));
    return std::string(start, end + 1);
}

// Charge les signatures depuis un fichier texte.
// Chaque ligne du fichier doit être du format :
// type:hex;severity:critique;pattern:deadbeef
// type:regex;severity:moyen;pattern:^GET\s
// type:ascii;severity:faible;pattern:ALERTE
std::vector<Signature> load_signatures(const std::string &filename) {
    std::vector<Signature> signatures;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Erreur: Impossible d'ouvrir le fichier " << filename << "\n";
        return signatures;
    }
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty())
            continue;
        Signature sig;
        std::istringstream iss(line);
        std::string token;
        while (std::getline(iss, token, ';')) {
            token = trim(token);
            auto pos = token.find(':');
            if (pos != std::string::npos) {
                std::string key = trim(token.substr(0, pos));
                std::string value = token.substr(pos + 1);
                // Pour type et severity, on convertit en minuscules afin de faciliter la comparaison
                std::string keyLower = key;
                std::transform(keyLower.begin(), keyLower.end(), keyLower.begin(), ::tolower);
                std::string valueLower = trim(value);
                std::transform(valueLower.begin(), valueLower.end(), valueLower.begin(), ::tolower);

                if (keyLower == "type") {
                    if (valueLower == "hex")
                        sig.type = SignatureType::HEX;
                    else if (valueLower == "regex")
                        sig.type = SignatureType::REGEX;
                    else
                        sig.type = SignatureType::ASCII;
                } else if (keyLower == "severity") {
                    if (valueLower == "critique")
                        sig.severity = Severity::CRITIQUE;
                    else if (valueLower == "moyen")
                        sig.severity = Severity::MOYEN;
                    else
                        sig.severity = Severity::FAIBLE;
                } else if (keyLower == "pattern") {
                    // Pour le pattern, nous conservons la casse originale et enlevons seulement les espaces superflus.
                    sig.pattern = trim(value);
                }
            }
        }
        signatures.push_back(sig);
    }
    return signatures;
}

// Vérifie si le payload correspond à une signature donnée
bool match_signature(const std::string &payload, const Signature &sig) {
    switch(sig.type) {
        case SignatureType::HEX: {
            // Pour les signatures HEX, effectue une recherche simple dans le payload.
            return payload.find(sig.pattern) != std::string::npos;
        }
        case SignatureType::REGEX: {
            try {
                std::regex rgx(sig.pattern);
                return std::regex_search(payload, rgx);
            } catch (const std::regex_error &e) {
                std::cerr << "Erreur regex pour le pattern '" << sig.pattern << "': " << e.what() << "\n";
                return false;
            }
        }
        case SignatureType::ASCII: {
            return payload.find(sig.pattern) != std::string::npos;
        }
    }
    return false;
}

// Charge des signatures par défaut intégrées en dur dans la base de signatures.
// Ceci est utile pour tester l'application sans fichier externe.
void loadDefaultSignatures(std::unordered_set<std::string>& signatureDatabase) {
    signatureDatabase.insert("deadbeef");
    signatureDatabase.insert("alerte");
    // Ajoutez d'autres signatures prédéfinies si nécessaire
}
