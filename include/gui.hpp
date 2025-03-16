#pragma once

#include <gtk/gtk.h>
#include <string>

#include "capture.hpp"

// Fonctions pour l'interface (ex: mise à jour du TextView)
void updateTextView(PacketCaptureData* captureData, const std::string& text);
gboolean idleUpdate(gpointer user_data);
void displayMatchMessage(PacketCaptureData* captureData);
void displayNoMatchMessage(PacketCaptureData* captureData);

// Callback pour le bouton
void on_button_clicked(GtkWidget *widget, gpointer data);
