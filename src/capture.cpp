#include "capture.hpp"
#include "gui.hpp"  // Pour avoir la définition complète de AppData et les fonctions d'interface (ex.: add_packet_to_list)
#include <gtk/gtk.h>
#include <tins/tins.h>
#include <thread>
#include <sstream>
#include <vector>
#include <memory>
#include <iomanip>
#include <chrono>
#include <iostream>
#include <tuple>
#include <fstream>
#include <exception>

using namespace Tins;

// --------------------------------------------------------------------------
// Structures PCAP pour l'export
// --------------------------------------------------------------------------
struct pcap_hdr_t {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // Correction GMT, 0 par défaut
    uint32_t sigfigs;        // 0 par défaut
    uint32_t snaplen;        // Longueur max des paquets capturés (ex. 65535)
    uint32_t network;        // 1 pour Ethernet
};

struct pcaprec_hdr_t {
    uint32_t ts_sec;    // Timestamp en secondes
    uint32_t ts_usec;   // Timestamp en microsecondes
    uint32_t incl_len;  // Nombre d'octets enregistrés pour ce paquet
    uint32_t orig_len;  // Longueur réelle du paquet
};

// --------------------------------------------------------------------------
// Fonction utilitaire : format_timestamp()
// Convertit un Tins::Timestamp en une chaîne formatée "YYYY-MM-DD HH:MM:SS.mmm"
// --------------------------------------------------------------------------
std::string format_timestamp(const Timestamp &ts) {
    auto time = std::chrono::system_clock::to_time_t(
                    std::chrono::system_clock::from_time_t(ts.seconds()));
    std::ostringstream oss;
    auto time_tm = *std::localtime(&time);
    oss << std::put_time(&time_tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(6) << std::setfill('0')
        << (ts.microseconds() / 1000);
    return oss.str();
}

// --------------------------------------------------------------------------
// Fonction : capture_packet()
// Extrait les informations d'un paquet capturé, met à jour l'interface via g_idle_add() 
// (en appelant les fonctions d'affichage du module GUI) et stocke le paquet dans app->packets.
// --------------------------------------------------------------------------
void capture_packet(AppData *app, const Packet &packet) {
    const PDU &pdu = *packet.pdu();
    const EthernetII *eth = pdu.find_pdu<EthernetII>();
    const IP *ip = pdu.find_pdu<IP>();

    std::string src = eth ? eth->src_addr().to_string() : "N/A";
    std::string dst = eth ? eth->dst_addr().to_string() : "N/A";
    std::string proto = ip ? "IP" : "Ethernet";
    std::string info = "Packet captured";
    std::string timestamp = format_timestamp(packet.timestamp());

    // Utilisation de g_idle_add pour effectuer la mise à jour de l'interface de manière thread-safe.
    g_idle_add([](gpointer data) -> gboolean {
        auto tuple_ptr = static_cast<std::tuple<AppData*, std::string, std::string,
                                                   std::string, std::string, std::string,
                                                   std::shared_ptr<Packet>>*>(data);
        AppData* app = std::get<0>(*tuple_ptr);
        std::string src = std::get<1>(*tuple_ptr);
        std::string dst = std::get<2>(*tuple_ptr);
        std::string proto = std::get<3>(*tuple_ptr);
        std::string info = std::get<4>(*tuple_ptr);
        std::string timestamp = std::get<5>(*tuple_ptr);
        std::shared_ptr<Packet> pkt = std::get<6>(*tuple_ptr);
        delete tuple_ptr;
        // Mise à jour de l'affichage via la fonction déclarée dans gui.hpp
        add_packet_to_list(app, src, dst, proto, info, timestamp);
        // Stockage du paquet pour l'export ultérieur
        app->packets.push_back(pkt);
        return FALSE;
    }, new std::tuple<AppData*, std::string, std::string,
                        std::string, std::string, std::string,
                        std::shared_ptr<Packet>>(
            app, src, dst, proto, info, timestamp, std::make_shared<Packet>(packet)
    ));
}

// --------------------------------------------------------------------------
// Fonction : sniffer_thread()
// Configure le sniffer via libtins et lance la capture des paquets sur l'interface
// sélectionnée dans l'UI. La boucle de capture continue tant que app->capturing est vrai.
// --------------------------------------------------------------------------
void sniffer_thread(AppData *app) {
    try {
        SnifferConfiguration config;
        if (!app->filter_expression.empty()) {
            config.set_filter(app->filter_expression);
        }
        config.set_promisc_mode(true);

        // Récupération de l'interface sélectionnée depuis la combo box (valeur par défaut : "eth0")
        gchar *iface = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(app->interface_combo));
        std::string interface_name = (iface) ? iface : "eth0";
        if (iface) {
            g_free(iface);
        }

        // Création du sniffer sur l'interface sélectionnée
        Sniffer sniffer(interface_name, config);

        while (app->capturing) {
            if (!app->paused) {
                Packet packet = sniffer.next_packet();
                capture_packet(app, packet);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } catch(const std::exception &ex) {
        std::cerr << "Erreur dans le thread de capture: " << ex.what() << std::endl;
    }
}

// --------------------------------------------------------------------------
// Fonction : export_packets_to_pcap()
// Exporte l'ensemble des paquets stockés dans app->packets dans un fichier PCAP
// (packets.pcap) pouvant être ouvert par Wireshark.
// --------------------------------------------------------------------------
void export_packets_to_pcap(AppData *app) {
    std::ofstream out("packets.pcap", std::ios::binary);
    if (!out) {
        std::cerr << "Erreur lors de l'ouverture du fichier packets.pcap pour écriture.\n";
        return;
    }

    // Écriture du header global PCAP
    pcap_hdr_t global_header;
    global_header.magic_number = 0xa1b2c3d4;
    global_header.version_major = 2;
    global_header.version_minor = 4;
    global_header.thiszone = 0;
    global_header.sigfigs = 0;
    global_header.snaplen = 65535;
    global_header.network = 1; // Ethernet

    out.write(reinterpret_cast<const char*>(&global_header), sizeof(global_header));

    // Pour chaque paquet, écrit l'enregistrement dans le fichier PCAP
    for (const auto &pkt_ptr : app->packets) {
        std::unique_ptr<PDU> cloned_pdu(pkt_ptr->pdu()->clone());
        std::vector<uint8_t> data = cloned_pdu->serialize();

        pcaprec_hdr_t record_header;
        record_header.ts_sec = pkt_ptr->timestamp().seconds();
        record_header.ts_usec = pkt_ptr->timestamp().microseconds();
        record_header.incl_len = data.size();
        record_header.orig_len = data.size();

        out.write(reinterpret_cast<const char*>(&record_header), sizeof(record_header));
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
    out.close();
    std::cout << "Packets exported to packets.pcap\n";
}

// --------------------------------------------------------------------------
// Callback du bouton "Exporter"
// Lance l'export des paquets stockés dans app->packets dans un fichier PCAP.
// --------------------------------------------------------------------------
void on_export_clicked(GtkButton *button, gpointer user_data) {
    AppData *app = static_cast<AppData *>(user_data);
    export_packets_to_pcap(app);
}

// --------------------------------------------------------------------------
// Callback du bouton "Démarrer/Pause"
// Gère le démarrage, la pause et l'arrêt de la capture.
// --------------------------------------------------------------------------
void on_start_clicked(GtkButton *button, gpointer user_data) {
    AppData *app = static_cast<AppData *>(user_data);
    if (!app->capturing) {
        const char *filter_text = gtk_entry_get_text(app->filter_entry);
        app->filter_expression = filter_text ? std::string(filter_text) : "";
        app->capturing = true;
        app->paused = false;
        std::thread(sniffer_thread, app).detach();
        gtk_button_set_label(button, "⏸ Pause");
    } else if (app->paused) {
        app->paused = false;
        gtk_button_set_label(button, "⏸ Pause");
    } else {
        app->capturing = false;
        gtk_button_set_label(button, "▶ Démarrer");
    }
}

// --------------------------------------------------------------------------
// Callback du bouton "Pause/Reprendre" (optionnel)
// Permet de mettre en pause ou de reprendre la capture si vous souhaitez avoir un bouton dédié.
// --------------------------------------------------------------------------
void on_pause_clicked(GtkButton *button, gpointer user_data) {
    AppData *app = static_cast<AppData *>(user_data);
    if (app->capturing && !app->paused) {
        app->paused = true;
        gtk_button_set_label(button, "▶ Reprendre");
    } else if (app->capturing && app->paused) {
        app->paused = false;
        gtk_button_set_label(button, "⏸ Pause");
    }
}

// --------------------------------------------------------------------------
// Callback du bouton "Stop Capture"
// Arrête la capture et réinitialise l'état.
// --------------------------------------------------------------------------
void on_stop_clicked(GtkButton *button, gpointer user_data) {
    AppData *app = static_cast<AppData *>(user_data);
    app->capturing = false;
    app->paused = false;
    gtk_button_set_label(button, "▶ Démarrer");
}
