#include "gui.hpp"
#include "capture.hpp"  // Pour accéder à PacketCaptureData
#include <gtk/gtk.h>
#include <iostream>
#include <string>
#include <utility>

// Pointeurs globaux pour les widgets principaux
static GtkBuilder* builder = nullptr;
static GtkWidget* mainWindow = nullptr;
static GtkTreeView* treeviewPackets = nullptr;
static GtkTextView* textviewLogs = nullptr;
static GtkListStore* packetListStore = nullptr;

/**
 * @brief Initialise l'interface graphique à partir du fichier Glade.
 *
 * Cette fonction charge l'interface, récupère les widgets essentiels et configure
 * le GtkTreeView pour afficher les informations des paquets.
 */
void init_gui(int* argc, char*** argv) {
    gtk_init(argc, argv);

    // Charger l'interface depuis le fichier Glade
    builder = gtk_builder_new();
    if (!gtk_builder_add_from_file(builder, "/home/oumar_tee/Bureau/projet_ids/interface.glade", nullptr)) {
        std::cerr << "Erreur: Impossible de charger /home/oumar_tee/Bureau/projet_ids/interface.glade" << std::endl;
        exit(1);
    }

    // Récupérer la fenêtre principale
    mainWindow = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));
    if (!mainWindow) {
        std::cerr << "Erreur: main_window introuvable dans interface.glade" << std::endl;
        exit(1);
    }

    // Récupérer le GtkTreeView pour les paquets et le GtkTextView pour les logs
    treeviewPackets = GTK_TREE_VIEW(gtk_builder_get_object(builder, "treeview_packets"));
    textviewLogs = GTK_TEXT_VIEW(gtk_builder_get_object(builder, "textview_logs"));

    // Créer et configurer le modèle de données pour le TreeView
    // Colonnes : 0 - Timestamp, 1 - Source, 2 - Destination, 3 - Protocole, 4 - Alerte
    packetListStore = gtk_list_store_new(5, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    gtk_tree_view_set_model(treeviewPackets, GTK_TREE_MODEL(packetListStore));
    g_object_unref(packetListStore);

    // Configuration des colonnes du TreeView et activation du tri

    // Colonne 0 : Timestamp
    GtkCellRenderer* renderer = gtk_cell_renderer_text_new();
    GtkTreeViewColumn* column = gtk_tree_view_column_new_with_attributes("Timestamp", renderer, "text", 0, nullptr);
    gtk_tree_view_append_column(treeviewPackets, column);
    gtk_tree_view_column_set_sort_column_id(column, 0);

    // Colonne 1 : Source
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Source", renderer, "text", 1, nullptr);
    gtk_tree_view_append_column(treeviewPackets, column);
    gtk_tree_view_column_set_sort_column_id(column, 1);

    // Colonne 2 : Destination
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Destination", renderer, "text", 2, nullptr);
    gtk_tree_view_append_column(treeviewPackets, column);
    gtk_tree_view_column_set_sort_column_id(column, 2);

    // Colonne 3 : Protocole
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Protocole", renderer, "text", 3, nullptr);
    gtk_tree_view_append_column(treeviewPackets, column);
    gtk_tree_view_column_set_sort_column_id(column, 3);

    // Colonne 4 : Alerte
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Alerte", renderer, "text", 4, nullptr);
    gtk_tree_view_append_column(treeviewPackets, column);
    gtk_tree_view_column_set_sort_column_id(column, 4);

    // Afficher tous les widgets de la fenêtre principale
    gtk_widget_show_all(mainWindow);
}

/**
 * @brief Ajoute une ligne dans le GtkTreeView pour afficher un paquet.
 *
 * @param timestamp   L'horodatage du paquet.
 * @param source      L'adresse source.
 * @param destination L'adresse destination.
 * @param protocol    Le protocole identifié.
 * @param alerte      Message d'alerte (s'il y a correspondance de signature).
 */
void add_packet_to_list(const std::string& timestamp,
                        const std::string& source,
                        const std::string& destination,
                        const std::string& protocol,
                        const std::string& alerte) {
    GtkTreeIter iter;
    gtk_list_store_append(packetListStore, &iter);
    gtk_list_store_set(packetListStore, &iter,
                       0, timestamp.c_str(),
                       1, source.c_str(),
                       2, destination.c_str(),
                       3, protocol.c_str(),
                       4, alerte.c_str(),
                       -1);
}

/**
 * @brief Met à jour le GtkTextView des logs en ajoutant un message.
 *
 * @param message Le message à ajouter.
 */
void update_log(const std::string& message) {
    GtkTextBuffer* buffer = gtk_text_view_get_buffer(textviewLogs);
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(buffer, &iter);
    gtk_text_buffer_insert(buffer, &iter, (message + "\n").c_str(), -1);
}

/**
 * @brief Met à jour le GtkTextView associé à PacketCaptureData.
 *
 * @param captureData Pointeur vers les données de capture.
 * @param message     Le message à insérer.
 */
void updateTextView(PacketCaptureData* captureData, const std::string& message) {
    if (!captureData || !captureData->buffer) {
        std::cerr << "Erreur : Buffer de texte non défini dans PacketCaptureData." << std::endl;
        return;
    }
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(captureData->buffer, &end);
    gtk_text_buffer_insert(captureData->buffer, &end, (message + "\n").c_str(), -1);
}

/**
 * @brief Fonction de mise à jour via g_idle_add.
 *
 * Cette fonction est appelée dans le thread principal pour mettre à jour l'interface
 * de façon thread-safe. On s'attend à recevoir un pointeur vers un std::pair<PacketCaptureData*, std::string>.
 *
 * @param user_data Données à traiter.
 * @return gboolean FALSE pour retirer la fonction de la boucle idle.
 */
gboolean idleUpdate(gpointer user_data) {
    auto data = static_cast<std::pair<PacketCaptureData*, std::string>*>(user_data);
    updateTextView(data->first, data->second);
    delete data;
    return FALSE;
}

/**
 * @brief Exemple de fonction de mise à jour via g_idle_add (non utilisée ici).
 *
 * @param data Données à traiter.
 * @return gboolean FALSE pour retirer la fonction de la boucle idle.
 */
gboolean idle_update_ui(gpointer data) {
    return FALSE;
}

/**
 * @brief Récupère le bouton de capture depuis l'interface.
 *
 * @return GtkWidget* pointeur vers le bouton "button_capture".
 */
GtkWidget* get_capture_button() {
    return GTK_WIDGET(gtk_builder_get_object(builder, "button_capture"));
}

/**
 * @brief Récupère le GtkTextBuffer associé au GtkTextView des logs.
 *
 * @return GtkTextBuffer* pointeur vers le buffer de texte.
 */
GtkTextBuffer* get_text_buffer() {
    return gtk_text_view_get_buffer(textviewLogs);
}
