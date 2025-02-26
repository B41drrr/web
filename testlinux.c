#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

void test_command_execution() {
    printf("[TEST] Tentative d'exécution d'une commande suspecte\n");
    system("echo 'test' > /tmp/malware_test.txt");  // Peut être remplacé par une commande plus suspecte
}

void test_memory_access() {
    printf("[TEST] Lecture de la mémoire d'un processus\n");
    pid_t target_pid = getppid(); // Cible : processus parent
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
    
    int fd = open(mem_path, O_RDONLY);
    if (fd == -1) {
        perror("[ERREUR] Impossible d'ouvrir la mémoire du processus");
        return;
    }
    
    char buffer[128];
    if (read(fd, buffer, sizeof(buffer)) > 0) {
        printf("[INFO] Lecture réussie\n");
    } else {
        perror("[ERREUR] Échec de la lecture de la mémoire");
    }
    close(fd);
}

void test_ptrace_injection() {
    printf("[TEST] Tentative d'injection avec ptrace\n");
    pid_t child = fork();
    
    if (child == 0) {  // Processus fils
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        printf("[INFO] Processus fils en mode trace\n");
        raise(SIGSTOP);  // Pause pour permettre au parent d'attacher ptrace
    } else if (child > 0) {  // Processus parent
        wait(NULL);  // Attendre que le fils soit stoppé
        if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == 0) {
            printf("[INFO] Attachement réussi\n");
            ptrace(PTRACE_DETACH, child, NULL, NULL);
        } else {
            perror("[ERREUR] Attachement ptrace");
        }
    } else {
        perror("[ERREUR] Fork échoué");
    }
}

int main() {
    printf("=== Test de détection comportementale d'un EDR ===\n");
    
    test_command_execution();
    test_memory_access();
    test_ptrace_injection();
    
    printf("=== Fin du test ===\n");
    return 0;
}
