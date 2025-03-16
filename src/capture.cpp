#include "capture.hpp"
#include <iostream>
#include <sstream>
#include <thread>
#include <algorithm>

// Fonctions GTK externes (pour mise à jour)
extern void updateTextView(PacketCaptureData*, const std::string&);
extern gboolean idleUpdate(gpointer user_data);

// Fonction de capture
void capturePackets(PacketCaptureData* captureData) {
    using namespace Tins;

    // Par exemple : Sniffer sniffer("enp0s3");
   Sniffer sniffer("wlan0");


    sniffer.sniff_loop([captureData](const PDU &pdu) -> bool {
        if (!captureData->captureRunning) {
            return false; // on arrête la capture
        }

        std::ostringstream packetDetails;

        // Exemple d'analyse Ethernet
        const EthernetII* ethernet = pdu.find_pdu<EthernetII>();
        if (ethernet) {
            packetDetails << "Source MAC: " << ethernet->src_addr() << "\n";
            packetDetails << "Destination MAC: " << ethernet->dst_addr() << "\n";
            packetDetails << "Ethernet II Frame\n";
        }

        // Exemple d’analyse IP
        const IP* ip = pdu.find_pdu<IP>();
        if (ip) {
            packetDetails << "Source IP: " << ip->src_addr() << "\n";
            packetDetails << "Destination IP: " << ip->dst_addr() << "\n";
            packetDetails << "IP Packet\n";
        }

        packetDetails << "\n";

        // Comparaison signature
        if (auto rawPDU = pdu.find_pdu<RawPDU>()) {
            auto& payload = rawPDU->payload();
            for (const auto &signature : captureData->signatureDatabase) {
                // Rechercher la signature dans la payload
                if (std::search(payload.begin(), payload.end(),
                                signature.begin(), signature.end()) != payload.end()) {
                    captureData->matchFound = true;
                    captureData->matchedSignature = signature;
                }
            }
        }

        // Préparer les données pour le thread principal
        auto data = new std::pair<PacketCaptureData*, std::string>(captureData, packetDetails.str());
        g_idle_add(idleUpdate, data);

        return true;
    });

    // Après la boucle
    // Afficher un message si pas de correspondance, etc.
}
