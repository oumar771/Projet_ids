#ifndef CAPTURE_HPP
#define CAPTURE_HPP

#include <tins/tins.h>
#include "gui.hpp"  // Ce fichier doit contenir la définition complète de AppData

// --------------------------------------------------------------------------
// Formate un Timestamp en une chaîne lisible au format "YYYY-MM-DD HH:MM:SS.mmm"
// --------------------------------------------------------------------------
std::string format_timestamp(const Tins::Timestamp &ts);

// --------------------------------------------------------------------------
// Traite un paquet capturé et met à jour l'interface utilisateur.
// La fonction est implémentée dans capture.cpp.
// --------------------------------------------------------------------------
void capture_packet(AppData *app, const Tins::Packet &packet);

// --------------------------------------------------------------------------
// Fonction exécutée par le thread de capture.
// Elle récupère l'interface sélectionnée dans l'interface utilisateur et
// capture les paquets en fonction d'un filtre (optionnel).
// --------------------------------------------------------------------------
void sniffer_thread(AppData *app);

// --------------------------------------------------------------------------
// Exporte l'ensemble des paquets capturés (stockés dans app->packets)
// dans un fichier PCAP qui pourra être ouvert par Wireshark.
// --------------------------------------------------------------------------
void export_packets_to_pcap(AppData *app);

#endif // CAPTURE_HPP
