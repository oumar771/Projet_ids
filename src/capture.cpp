#include "gui.hpp"         // Pour update_log, updateTextView, etc.
#include "capture.hpp"
#include "signature.hpp"   // Pour match_signature et la structure Signature
#include <iostream>
#include <sstream>
#include <thread>
#include <algorithm>
#include <exception>
#include <tins/tins.h>
#include <ctime>

using namespace Tins;

// Fonctions GTK externes (définies dans gui.cpp)
extern void updateTextView(PacketCaptureData*, const std::string&);
extern gboolean idleUpdate(gpointer user_data);

// Nouvelle version de detectSignature utilisant match_signature pour chaque signature
void detectSignature(PacketCaptureData* captureData, const PDU& pdu) {
    // Convertir le payload en string
    if (auto rawPDU = pdu.find_pdu<RawPDU>()) {
        std::string payload(rawPDU->payload().begin(), rawPDU->payload().end());
        for (const auto &sig : captureData->signatureDatabase) {
            if (match_signature(payload, sig)) {
                captureData->matchFound = true;
                captureData->matchedSignature = sig.pattern;
                update_log("Alerte : signature détectée (" + sig.pattern + ")");
                break;
            }
        }
    }
}

// Fonction helper pour mettre à jour le GtkTreeView via le thread UI
// On passe les informations dans un tuple : (captureData, timestamp, source IP, destination IP, protocole, alerte)
gboolean idle_update_list(gpointer data) {
    auto info = static_cast<std::tuple<PacketCaptureData*, std::string, std::string, std::string, std::string, std::string>*>(data);
    PacketCaptureData* capData = std::get<0>(*info);
    std::string timestamp = std::get<1>(*info);
    std::string src = std::get<2>(*info);
    std::string dst = std::get<3>(*info);
    std::string proto = std::get<4>(*info);
    std::string alert = std::get<5>(*info);
    add_packet_to_list(timestamp, src, dst, proto, alert);
    delete info;
    return FALSE;
}

void capturePackets(PacketCaptureData* captureData) {
    try {
        // Utilisation de l'interface et du filtre BPF configurés dans captureData
        std::string iface = captureData->interfaceName;   // Par ex. "wlan0" ou "enp0s3"
        std::string bpf_filter = captureData->bpfFilter;    // Peut être vide si non défini

        // Configuration du sniffer avec le filtre BPF si défini
        Tins::SnifferConfiguration config;
        if (!bpf_filter.empty()) {
            config.set_filter(bpf_filter);
        }

        // Initialisation du sniffer avec l'interface et la configuration
        Tins::Sniffer sniffer(iface, config);

        sniffer.sniff_loop([captureData](const PDU &pdu) -> bool {
            if (!captureData->captureRunning) {
                return false; // Arrêt de la capture si demandé
            }

            // Message de debug pour confirmer la réception d'un paquet
            std::cout << "Paquet capturé !" << std::endl;
            update_log("Paquet capturé sur " + captureData->interfaceName);

            std::ostringstream packetDetails;

            // Analyse Ethernet
            if (const EthernetII* ethernet = pdu.find_pdu<EthernetII>()) {
                packetDetails << "Ethernet II Frame\n";
                packetDetails << "Source MAC: " << ethernet->src_addr() << "\n";
                packetDetails << "Destination MAC: " << ethernet->dst_addr() << "\n";
            }

            // Analyse IP
            std::string source_ip = "unknown";
            std::string destination_ip = "unknown";
            if (const IP* ip = pdu.find_pdu<IP>()) {
                packetDetails << "IP Packet\n";
                source_ip = ip->src_addr().to_string();
                destination_ip = ip->dst_addr().to_string();
                packetDetails << "Source IP: " << source_ip << "\n";
                packetDetails << "Destination IP: " << destination_ip << "\n";
            }

            // Analyse TCP
            std::string protocol = "unknown";
            if (const TCP* tcp = pdu.find_pdu<TCP>()) {
                protocol = "TCP";
                packetDetails << "TCP Packet\n";
                packetDetails << "Source Port: " << tcp->sport() << "\n";
                packetDetails << "Destination Port: " << tcp->dport() << "\n";
                if (tcp->sport() == 80 || tcp->dport() == 80) {
                    packetDetails << "Possibilité de HTTP détecté\n";
                }
            }
            // Analyse UDP
            else if (const UDP* udp = pdu.find_pdu<UDP>()) {
                protocol = "UDP";
                packetDetails << "UDP Packet\n";
                packetDetails << "Source Port: " << udp->sport() << "\n";
                packetDetails << "Destination Port: " << udp->dport() << "\n";
                if (udp->sport() == 53 || udp->dport() == 53) {
                    packetDetails << "Possibilité de DNS détecté\n";
                    if (const DNS* dns = pdu.find_pdu<DNS>()) {
                        if (!dns->queries().empty()) {
                            packetDetails << "DNS Query: ";
                            for (const auto &query : dns->queries()) {
                                packetDetails << query.dname() << " ";
                            }
                            packetDetails << "\n";
                        } else {
                            packetDetails << "DNS Response\n";
                        }
                    }
                }
            }
            packetDetails << "\n";

            // Détection de signature
            detectSignature(captureData, pdu);

            // Récupérer l'heure actuelle pour le timestamp
            time_t now = time(0);
            char* dt = ctime(&now);
            std::string timestamp(dt);
            if (!timestamp.empty() && timestamp.back() == '\n') {
                timestamp.pop_back();
            }

            // Préparer une alerte en cas de détection de signature
            std::string alert = captureData->matchFound ? "Signature match" : "";

            // Préparer les données pour mettre à jour le GtkTreeView via le thread UI
            auto list_data = new std::tuple<PacketCaptureData*, std::string, std::string, std::string, std::string, std::string>(
                captureData, timestamp, source_ip, destination_ip, protocol, alert
            );
            g_idle_add(idle_update_list, list_data);

            // Mettre à jour le GtkTextView avec les détails du paquet
            auto text_data = new std::pair<PacketCaptureData*, std::string>(captureData, packetDetails.str());
            g_idle_add(idleUpdate, text_data);

            return true;
        });
    }
    catch(const std::exception& ex) {
        std::cerr << "Erreur lors de la capture : " << ex.what() << std::endl;
        updateTextView(captureData, "Erreur de capture : " + std::string(ex.what()));
    }
}
