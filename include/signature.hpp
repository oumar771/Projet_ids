#pragma once

#include <string>
#include <vector>
#include <regex>
#include <unordered_set>

// Enum pour le type de signature
enum class SignatureType { HEX, REGEX, ASCII };

// Enum pour la sévérité de l'alerte
enum class Severity { FAIBLE, MOYEN, CRITIQUE };

// Structure représentant une signature
struct Signature {
    SignatureType type;
    Severity severity;
    std::string pattern;
};

// Charge les signatures depuis un fichier texte.
// Chaque ligne du fichier doit respecter le format suivant, par exemple :
// type:hex;severity:critique;pattern:deadbeef
std::vector<Signature> load_signatures(const std::string &filename);

// Vérifie si la signature correspond à la charge utile (payload).
bool match_signature(const std::string &payload, const Signature &sig);

// Charge des signatures par défaut intégrées en dur dans la base de signatures.
// Ceci est utile pour tester l'application sans fichier externe.
void loadDefaultSignatures(std::unordered_set<std::string>& signatureDatabase);
