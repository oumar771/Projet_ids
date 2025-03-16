#include "gui.hpp"
#include <sstream>
#include <thread>


// Mettre à jour la zone de texte
void updateTextView(PacketCaptureData *captureData, const std::string& packetDetails) {
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(captureData->buffer, &iter);

    gchar *packetInfo = g_strdup(packetDetails.c_str());
    gtk_text_buffer_insert(captureData->buffer, &iter, packetInfo, -1);
    g_free(packetInfo);
}

// Affichage si correspondance trouvée
void displayMatchMessage(PacketCaptureData* captureData) {
    if (captureData->matchFound) {
        std::string matchMessage = "Alerte : Correspondance détectée : " + captureData->matchedSignature + "\n";
        updateTextView(captureData, matchMessage);
    }
    captureData->matchFound = false;
}

// Affichage si aucune correspondance
void displayNoMatchMessage(PacketCaptureData* captureData) {
    if (!captureData->matchFound) {
        updateTextView(captureData, "Aucune correspondance trouvée.\n");
    }
}

gboolean idleUpdate(gpointer user_data) {
    auto *data = static_cast<std::pair<PacketCaptureData *, std::string> *>(user_data);
    updateTextView(data->first, data->second);
    displayMatchMessage(data->first);
    displayNoMatchMessage(data->first);
    delete data;
    return G_SOURCE_REMOVE;
}

// Callback du bouton
void on_button_clicked(GtkWidget *widget, gpointer data) {
    auto captureData = static_cast<PacketCaptureData*>(data);

    if (!captureData->captureRunning) {
        captureData->captureRunning = true;
        // Lancement du thread de capture
        std::thread(capturePackets, captureData).detach();
    } else {
        captureData->captureRunning = false;
    }
}
