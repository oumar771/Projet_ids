#ifndef GUI_HPP
#define GUI_HPP

#include <gtk/gtk.h>
#include <tins/tins.h>
#include <string>
#include <vector>
#include <memory>

// Structure regroupant l’état et les éléments de l’interface graphique.
struct AppData {
    GtkListStore *list_store;
    GtkTextBuffer *hex_buffer;
    GtkEntry *filter_entry;
    GtkComboBox *interface_combo;
    bool capturing;
    bool paused;
    std::vector<std::shared_ptr<Tins::Packet>> packets;
    std::string filter_expression;
};

// Déclarations des fonctions d'interface.
void add_packet_to_list(AppData *app,
                        const std::string &src,
                        const std::string &dst,
                        const std::string &proto,
                        const std::string &info,
                        const std::string &timestamp);
std::string bytes_to_hex(const std::vector<uint8_t>& data, size_t start, size_t end);
void show_packet_details(const Tins::Packet &packet);
void on_row_activated(GtkTreeView *tree_view,
                      GtkTreePath *path,
                      GtkTreeViewColumn *column,
                      gpointer user_data);
GtkWidget* create_packet_table(AppData *app);

// Déclarations des callbacks pour les boutons.
void on_start_clicked(GtkButton *button, gpointer user_data);
void on_stop_clicked(GtkButton *button, gpointer user_data);
void on_pause_clicked(GtkButton *button, gpointer user_data);
void on_export_clicked(GtkButton *button, gpointer user_data);  // <-- Assurez-vous que cette ligne est présente

#endif // GUI_HPP
