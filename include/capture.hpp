#pragma once

#include <tins/tins.h>
#include <gtk/gtk.h>
#include <string>
#include <unordered_set>

// Structure pour stocker les infos de capture
struct PacketCaptureData {
    GtkTextBuffer *buffer;
    bool captureRunning;
    GMutex mutex;
    std::unordered_set<std::string> signatureDatabase;
    bool matchFound;
    std::string matchedSignature;
};

// Déclare la fonction qui démarre la capture
void capturePackets(PacketCaptureData* captureData);
