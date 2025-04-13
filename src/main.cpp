#include <gtk/gtk.h>
#include "gui.hpp"
#include "capture.hpp"

int main(int argc, char *argv[]) {
    // Initialisation de l'environnement GTK
    gtk_init(&argc, &argv);

    // Création et initialisation de la structure globale AppData
    AppData app = {};
    app.capturing = false;
    app.paused = false;

    // Création de la fenêtre principale
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "🌐 Sniffer Réseau");
    gtk_window_set_default_size(GTK_WINDOW(window), 1200, 750);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Création d'un conteneur vertical (vbox) pour organiser l'interface
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // En-tête : titre de l'application
    GtkWidget *header = gtk_label_new("<span font='18' weight='bold'>Analyseur de Paquets Réseau</span>");
    gtk_label_set_use_markup(GTK_LABEL(header), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), header, FALSE, FALSE, 10);

    // Zone de saisie du filtre BPF
    GtkWidget *filter_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), filter_box, FALSE, FALSE, 5);
    GtkWidget *filter_label = gtk_label_new("Filtre BPF (optionnel) :");
    gtk_box_pack_start(GTK_BOX(filter_box), filter_label, FALSE, FALSE, 5);
    app.filter_entry = GTK_ENTRY(gtk_entry_new());
    gtk_box_pack_start(GTK_BOX(filter_box), GTK_WIDGET(app.filter_entry), TRUE, TRUE, 5);

    // Sélecteur d'interface réseau
    GtkWidget *interface_label = gtk_label_new("Sélectionner l'interface :");
    gtk_box_pack_start(GTK_BOX(vbox), interface_label, FALSE, FALSE, 5);
    app.interface_combo = GTK_COMBO_BOX(gtk_combo_box_text_new());
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.interface_combo), "eth0");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.interface_combo), "wlan0");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.interface_combo), "lo");
    gtk_box_pack_start(GTK_BOX(vbox), GTK_WIDGET(app.interface_combo), FALSE, FALSE, 5);

    // Bouton unique de capture qui gère le démarrage et l'arrêt de la capture.
    // S'il n'est pas en capture, le bouton démarre la capture et change son libellé en "⏸ Pause".
    // Sinon, il arrête la capture et remet le libellé à "▶ Démarrer".
    GtkWidget *capture_button = gtk_button_new_with_label("▶ Démarrer");
    gtk_widget_set_size_request(capture_button, 150, 40);
    gtk_box_pack_start(GTK_BOX(vbox), capture_button, FALSE, FALSE, 0);
    g_signal_connect(capture_button, "clicked", G_CALLBACK(on_start_clicked), &app);

    // Bouton "Exporter" pour sauvegarder les paquets capturés dans un fichier PCAP.
    GtkWidget *export_button = gtk_button_new_with_label("Exporter");
    gtk_widget_set_size_request(export_button, 150, 40);
    gtk_box_pack_start(GTK_BOX(vbox), export_button, FALSE, FALSE, 0);
    g_signal_connect(export_button, "clicked", G_CALLBACK(on_export_clicked), &app);

    // Tableau de visualisation des paquets capturés
    GtkWidget *packet_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(packet_scroll, -1, 350);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(packet_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), packet_scroll, TRUE, TRUE, 5);
    GtkWidget *packet_table = create_packet_table(&app);
    gtk_container_add(GTK_CONTAINER(packet_scroll), packet_table);
    // Connecte le callback pour le double-clic afin d'afficher les détails du paquet
    g_signal_connect(packet_table, "row-activated", G_CALLBACK(on_row_activated), &app);

    // Zone d'affichage hexadécimale pour voir les détails des paquets sélectionnés
    GtkWidget *hex_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(hex_scroll, -1, 200);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(hex_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), hex_scroll, TRUE, TRUE, 5);
    GtkWidget *hex_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(hex_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(hex_view), FALSE);
    gtk_container_add(GTK_CONTAINER(hex_scroll), hex_view);
    app.hex_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(hex_view));

    // Affichage de la fenêtre principale
    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
