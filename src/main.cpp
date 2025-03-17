#include <gtk/gtk.h>
#include <thread>
#include "gui.hpp"
#include "capture.hpp"
#include "signature.hpp"

// Thread global pour la capture
std::thread captureThread;

// Callback du bouton "Démarrer/Arrêter la capture"
extern "C" void on_button_clicked(GtkButton *button, gpointer user_data) {
    PacketCaptureData* data = static_cast<PacketCaptureData*>(user_data);
    
    if (!data->captureRunning) {
        // Démarrer la capture dans un thread séparé
        data->captureRunning = true;
        captureThread = std::thread(capturePackets, data);
        update_log("Capture démarrée.");
    } else {
        // Arrêter la capture
        data->captureRunning = false;
        if (captureThread.joinable()) {
            captureThread.join();
        }
        update_log("Capture arrêtée.");
    }
}

int main(int argc, char *argv[]) {
    // Initialiser l'interface via Glade (init_gui se charge de tout configurer)
    init_gui(&argc, &argv);

    // Préparer les données de capture
    PacketCaptureData captureData;
    captureData.captureRunning = false;
    g_mutex_init(&captureData.mutex);
    captureData.matchFound = false;
    
    // Récupérer le GtkTextBuffer associé au GtkTextView et l'affecter à captureData.buffer
    captureData.buffer = get_text_buffer();
    
    // Charger les signatures depuis un fichier (chemin absolu)
    // On affecte directement le vecteur retourné à signatureDatabase.
    captureData.signatureDatabase = load_signatures("/home/oumar_tee/Bureau/projet_ids/signatures.txt");
    
    // Définir des valeurs par défaut pour l'interface réseau et le filtre BPF
    captureData.interfaceName = "wlan0"; // Assurez-vous que cette interface existe sur votre machine
    captureData.bpfFilter = "";

    // Récupérer le bouton "Démarrer/Arrêter la capture" via la fonction get_capture_button()
    GtkWidget *button = get_capture_button();
    if (!button) {
        g_print("Erreur: Bouton 'button_capture' non trouvé dans l'interface Glade.\n");
        return 1;
    }
    // Connecter le signal "clicked" au callback on_button_clicked
    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), &captureData);

    // Lancer la boucle principale GTK
    gtk_main();

    // S'assurer que le thread de capture se termine correctement
    if (captureThread.joinable())
        captureThread.join();

    return 0;
}
