#pragma once

#include <tins/tins.h>
#include <gtk/gtk.h>
#include <string>
#include <vector>
#include "signature.hpp"  // Pour le type Signature

// Structure pour stocker les infos de capture
struct PacketCaptureData {
    GtkTextBuffer *buffer;
    bool captureRunning;
    GMutex mutex;
    std::vector<Signature> signatureDatabase; // Utiliser vector<Signature>
    bool matchFound;
    std::string matchedSignature;
    std::string interfaceName;
    std::string bpfFilter;
};

// Déclare la fonction qui démarre la capture
void capturePackets(PacketCaptureData* captureData);
