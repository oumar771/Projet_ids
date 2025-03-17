#pragma once

#include <string>
#include <gtk/gtk.h>

// Initialise l'interface graphique depuis le fichier Glade.
// argc et argv sont passés par référence afin de permettre une éventuelle modification.
void init_gui(int* argc, char*** argv);

// Ajoute une ligne dans le GtkTreeView pour afficher les informations d'un paquet.
// Les paramètres représentent respectivement le timestamp, l'adresse source, l'adresse destination,
// le protocole et un message d'alerte.
void add_packet_to_list(const std::string& timestamp,
                        const std::string& source,
                        const std::string& destination,
                        const std::string& protocol,
                        const std::string& alerte);

// Met à jour le GtkTextView des logs en ajoutant un message.
// Cette fonction peut être appelée pour afficher des alertes ou autres messages.
void update_log(const std::string& message);

// Fonction de mise à jour de l'interface, utilisée via g_idle_add pour des appels thread-safe.
// "data" peut contenir des informations à mettre à jour dans l'UI.
gboolean idle_update_ui(gpointer data);

// Récupère le bouton de capture depuis l'interface Glade.
GtkWidget* get_capture_button();

// Récupère le GtkTextBuffer associé au GtkTextView des logs.
GtkTextBuffer* get_text_buffer();
