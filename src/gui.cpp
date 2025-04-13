#include "gui.hpp"
#include "capture.hpp" // Pour éventuellement accéder à certaines fonctions communes
#include <gtk/gtk.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <memory>

// --------------------------------------------------------------------------
// Fonction : bytes_to_hex
// Convertit une plage d’un vecteur d’octets en une chaîne hexadécimale lisible
// --------------------------------------------------------------------------
std::string bytes_to_hex(const std::vector<uint8_t>& data, size_t start, size_t end) {
    std::ostringstream oss;
    for (size_t i = start; i < end && i < data.size(); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]) << " ";
    }
    return oss.str();
}

// --------------------------------------------------------------------------
// Fonction : add_packet_to_list
// Ajoute une ligne dans le GtkListStore pour afficher les informations d'un paquet
// --------------------------------------------------------------------------
void add_packet_to_list(AppData *app,
                        const std::string &src,
                        const std::string &dst,
                        const std::string &proto,
                        const std::string &info,
                        const std::string &timestamp) {
    GtkTreeIter iter;
    gtk_list_store_append(app->list_store, &iter);
    gtk_list_store_set(app->list_store, &iter,
                       0, src.c_str(),
                       1, dst.c_str(),
                       2, proto.c_str(),
                       3, info.c_str(),
                       4, timestamp.c_str(),
                       -1);
}

// --------------------------------------------------------------------------
// Fonction : show_packet_details
// Affiche une fenêtre de dialogue présentant les détails d'un paquet
// --------------------------------------------------------------------------
void show_packet_details(const Tins::Packet &packet) {
    const Tins::PDU &pdu = *packet.pdu();
    const Tins::IP *ip = pdu.find_pdu<Tins::IP>();
    const Tins::TCP *tcp = pdu.find_pdu<Tins::TCP>();
    const Tins::UDP *udp = pdu.find_pdu<Tins::UDP>();

    std::ostringstream details;
    details << "========= INFOS GÉNÉRALES =========\n";
    if (ip) {
        details << "Source IP : " << ip->src_addr() << "\n";
        details << "Destination IP : " << ip->dst_addr() << "\n";
    }
    if (tcp) {
        details << "Protocole : TCP\n";
        details << "Port Source : " << tcp->sport() << "\n";
        details << "Port Destination : " << tcp->dport() << "\n";
    } else if (udp) {
        details << "Protocole : UDP\n";
        details << "Port Source : " << udp->sport() << "\n";
        details << "Port Destination : " << udp->dport() << "\n";
    }

    // Clonage du PDU pour obtenir une instance non-const et pouvoir sérialiser
    std::unique_ptr<Tins::PDU> cloned_pdu(pdu.clone());
    auto raw_data = cloned_pdu->serialize();
    size_t header_size = 54;
    size_t payload_size = (raw_data.size() > header_size) ? (raw_data.size() - header_size - 4) : 0;

    details << "\n========= HEADER =========\n"
            << bytes_to_hex(raw_data, 0, header_size) << "\n";
    details << "\n========= PAYLOAD =========\n";
    if (payload_size > 0)
        details << bytes_to_hex(raw_data, header_size, header_size + payload_size) << "\n";
    else
        details << "Pas de Payload\n";
    details << "\n========= TRAILER =========\n";
    if (raw_data.size() > header_size + payload_size)
        details << bytes_to_hex(raw_data, header_size + payload_size, raw_data.size()) << "\n";
    else
        details << "Pas de Trailer\n";

    // Création de la fenêtre de dialogue
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Détails du Paquet",
                                                    NULL,
                                                    GTK_DIALOG_MODAL,
                                                    "_Fermer", GTK_RESPONSE_CLOSE,
                                                    NULL);
    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *text_view = gtk_text_view_new();

    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text_view), FALSE);

    gtk_container_add(GTK_CONTAINER(scroll), text_view);
    gtk_container_add(GTK_CONTAINER(content_area), scroll);
    gtk_widget_set_size_request(scroll, 600, 400);

    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    gtk_text_buffer_set_text(buffer, details.str().c_str(), -1);

    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// --------------------------------------------------------------------------
// Fonction : on_row_activated
// Callback déclenché lors d'un double-clic sur une ligne de la table,
// affichant les détails du paquet correspondant.
// --------------------------------------------------------------------------
void on_row_activated(GtkTreeView *tree_view,
                      GtkTreePath *path,
                      GtkTreeViewColumn *column,
                      gpointer user_data) {
    AppData *app = static_cast<AppData *>(user_data);
    int index = gtk_tree_path_get_indices(path)[0];
    if (index >= 0 && index < static_cast<int>(app->packets.size())) {
        show_packet_details(*app->packets[index]);
    }
}

// --------------------------------------------------------------------------
// Fonction : create_packet_table
// Crée et retourne un GtkTreeView configuré pour afficher la liste des paquets capturés.
// Le modèle comporte cinq colonnes : Source, Destination, Protocole, Info et Timestamp.
// --------------------------------------------------------------------------
GtkWidget* create_packet_table(AppData *app) {
    app->list_store = gtk_list_store_new(5,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    GtkWidget *treeview = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->list_store));
    
    const char *columns[] = {"Source", "Destination", "Protocole", "Info", "Timestamp"};
    for (int i = 0; i < 5; ++i) {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(columns[i], renderer, "text", i, NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);
    }
    gtk_widget_set_hexpand(treeview, TRUE);
    gtk_widget_set_vexpand(treeview, TRUE);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(treeview), TRUE);

    // Connexion du signal de double-clic pour afficher les détails du paquet
    g_signal_connect(treeview, "row-activated", G_CALLBACK(on_row_activated), app);

    return treeview;
}
