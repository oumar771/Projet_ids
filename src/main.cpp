#include <gtk/gtk.h>
#include "capture.hpp"
#include "gui.hpp"
#include "signature.hpp" // si besoin

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    // Création de la fenêtre
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Projet IDS");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), nullptr);

    // Layout principal
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(window), box);

    // Bouton
    GtkWidget *button = gtk_button_new_with_label("Démarrer/Arrêter la capture");
    gtk_box_pack_start(GTK_BOX(box), button, FALSE, FALSE, 0);

    // Zone de texte
    GtkWidget *textview = gtk_text_view_new();
    gtk_box_pack_start(GTK_BOX(box), textview, TRUE, TRUE, 0);

    gtk_widget_show_all(window);

    // Données de capture
    PacketCaptureData captureData;
    captureData.buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
    captureData.captureRunning = false;
    g_mutex_init(&captureData.mutex);
    captureData.matchFound = false;

    // Charger les signatures par défaut
    loadDefaultSignatures(captureData.signatureDatabase);

    // Connecter le bouton
    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), &captureData);

    gtk_main();
    return 0;
}
