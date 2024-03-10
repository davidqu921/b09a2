/**
 * Program: System Monitoring Tool
 * Description: For this program we will build a tool to display 
 * the tables used by the OS to keep track of open files, assignation 
 * of File Descriptors (FD) and processes.
 * 
 * Author: David Qu
 * Date Created: March 1, 2024
 * Last Modified: March 9, 2024
 * 
 * StudentID: 1007653585
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#define MAX_PATH_LEN 256
#define MAX_FILENAME_LEN 256

// Function prototypes
void display_process_fd_table(pid_t pid);
void display_systemwide_fd_table(pid_t pid);
void display_vnodes_fd_table(pid_t pid);
void display_composed_table(pid_t pid);
void flag_offending_processes(int threshold);
void display_usage();
int isPid(char* string);
void save_composite_table_text(const char *filename, pid_t pid);
void save_composite_table_binary(const char *filename, pid_t pid);


int main(int argc, char *argv[]) {
    // Parse command-line arguments
    int per_process = 0, system_wide = 0, vnodes = 0, composite = 0, save_text = 0, save_binary = 0;
    int threshold = -1;
    pid_t pid = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--per-process") == 0){
            per_process = 1;
        }
        else if (strcmp(argv[i], "--systemWide") == 0){
            system_wide = 1;
        }
        else if (strcmp(argv[i], "--Vnodes") == 0){
            vnodes = 1;
        }
        else if (strcmp(argv[i], "--composite") == 0){
            composite = 1;
        }
        else if (strncmp(argv[i], "--threshold=", 12) == 0){
            int lenOfNum = strlen(argv[i]) - 12;
            char num[lenOfNum+1];
            strncpy(num,argv[i]+12,lenOfNum+1);
            threshold = atoi(num);
        }
        else if (isPid(argv[i])){
            pid = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "--output_TXT") == 0){
            save_text = 1;
        }
        else if(strcmp(argv[i], "--output_binary") == 0){
            save_binary = 1;
        }
        else{
            printf("Unknown argument: %s\n", argv[i]);
			display_usage();
			exit(EXIT_FAILURE);
        }
    }

    // Default behavior
    if (!(per_process || system_wide || vnodes || composite || save_text || save_binary)){
        composite = 1;
    }

    // Display requested tables
    if (per_process){
        display_process_fd_table(pid);
    }
    if (system_wide){
        display_systemwide_fd_table(pid);
    }
    if (vnodes){
        display_vnodes_fd_table(pid);
    }
    if (composite){
        display_composed_table(pid);
    }

    // Flag offending processes if threshold is provided
    if (threshold != -1){
        flag_offending_processes(threshold);
    }

    // output the stdout as a text file or binary file
    if (save_text){
        save_composite_table_text("compositeTable.txt",pid);
    }
    if (save_binary){
        save_composite_table_binary("compositeTable.txt",pid);
    }


    printf("\n*******Program Terminated Successfuly!*******\n");

    return 0;
}

void display_process_fd_table(pid_t pid) {
    char proc_fd_path[MAX_PATH_LEN];
    DIR *dir;
    struct dirent *entry;

    printf("PID\tFD\n");
    printf("========================================\n");

    if(pid!=-1 && kill(pid, 0) != -1){ // PID is specified
        snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%d/fd", pid);
        dir = opendir(proc_fd_path);
        if (dir == NULL) {
            perror("Error opening directory\n");
            exit(EXIT_FAILURE);
        }

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char fd_path[MAX_PATH_LEN];
                char filename[MAX_FILENAME_LEN];
                ssize_t readlink_size;

                snprintf(fd_path, MAX_PATH_LEN, "%s/%s", proc_fd_path, entry->d_name);
                readlink_size = readlink(fd_path, filename, MAX_FILENAME_LEN - 1);
                if (readlink_size != -1) {
                    filename[readlink_size] = '\0';
                    printf("%d\t%s\n", pid, entry->d_name);
                } 
                else {
                    perror("Error reading link\n");
                }
            }
        }

        closedir(dir);
    }

    else if(pid==-1){ // PID not given
        ssize_t bufsize = 256;
        char linkname[bufsize];
        
        // Open the /proc directory
        dir = opendir("/proc");
        if (dir == NULL) {
            perror("Error opening /proc directory\n");
            exit(EXIT_FAILURE);
        }

        // Traverse each process directory
        while ((entry = readdir(dir)) != NULL) {
            // Skip non-process directories
            if (!isdigit(entry->d_name[0])) continue;

            int check_pid = atoi(entry->d_name);
            // check if we have permission to access this pid 
            if (kill(check_pid, 0) == -1) {
                continue; 
            }

            snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%s/fd/", entry->d_name);

            DIR *fd_dir = opendir(proc_fd_path);
            if (fd_dir != NULL) {
                // Traverse each file descriptor entry
                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    // Skip "." and ".." entries
                    if (strcmp(fd_entry->d_name, ".") == 0 || strcmp(fd_entry->d_name, "..") == 0)
                        continue;

                    // Construct the file descriptor path
                    char fd_path[MAX_PATH_LEN];
                    snprintf(fd_path, MAX_PATH_LEN, "%s%s", proc_fd_path, fd_entry->d_name);

                    // Read the symbolic link to get the file name
                    ssize_t len = readlink(fd_path, linkname, bufsize - 1);
                    if (len != -1) {
                        linkname[len] = '\0'; // Null-terminate the string
                        printf("%s\t%s\n", entry->d_name, fd_entry->d_name);
                    }
                    else {
                    perror("Error reading link\n");
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }
    printf("========================================\n");
}

void display_systemwide_fd_table(pid_t pid) {
    // Implement system-wide FD table display
    char proc_fd_path[MAX_PATH_LEN];
    DIR *dir;
    struct dirent *entry;

    printf("PID\tFD\tFilename\n");
    printf("========================================\n");


    if (pid!=-1 && kill(pid, 0) != -1){
        snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%d/fd", pid);
        dir = opendir(proc_fd_path);
        if (dir == NULL) {
            perror("Error opening directory\n");
            exit(EXIT_FAILURE);
        }

        while ((entry = readdir(dir)) != NULL) {
 
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char fd_path[MAX_PATH_LEN];
                char filename[MAX_FILENAME_LEN];
                ssize_t readlink_size;

                snprintf(fd_path, MAX_PATH_LEN, "%s/%s", proc_fd_path, entry->d_name);
                readlink_size = readlink(fd_path, filename, MAX_FILENAME_LEN - 1);
                if (readlink_size != -1) {
                    filename[readlink_size] = '\0';
                    printf("%d\t%s\t%s\n", pid, entry->d_name, filename);
                } 
                else {
                    perror("Error reading link\n");
                }
            }
        }

        closedir(dir);
    }

    else if(pid==-1){
        ssize_t bufsize = 256;
        char linkname[bufsize];

        // Open the /proc directory
        dir = opendir("/proc");
        if (dir == NULL) {
            perror("Error opening /proc directory\n");
            exit(EXIT_FAILURE);
        }

        // Traverse each process directory
        while ((entry = readdir(dir)) != NULL) {
            // Skip non-process directories
            if (!isdigit(entry->d_name[0])){
                continue;
            }
            
            int check_pid = atoi(entry->d_name);
            // check if we have permission to access this pid 
            if (kill(check_pid, 0) == -1) {
                continue; 
            }

            snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%s/fd/", entry->d_name);

            // Open the file descriptor directory of the process
            DIR *fd_dir = opendir(proc_fd_path);
            if (fd_dir != NULL) {
                // Traverse each file descriptor entry
                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    // Skip "." and ".." entries
                    if (strcmp(fd_entry->d_name, ".") == 0 || strcmp(fd_entry->d_name, "..") == 0)
                        continue;

                    // Construct the file descriptor path
                    char fd_path[MAX_PATH_LEN];
                    snprintf(fd_path, MAX_PATH_LEN, "%s%s", proc_fd_path, fd_entry->d_name);

                    // Read the symbolic link to get the file name
                    ssize_t len = readlink(fd_path, linkname, bufsize - 1);
                    if (len != -1) {
                        linkname[len] = '\0'; // Null-terminate the string
                        printf("%s\t%s\t%s\n", entry->d_name, fd_entry->d_name, linkname);
                    }
                    else {
                        perror("Error reading link\n");
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }
    printf("========================================\n");
}

void display_vnodes_fd_table(pid_t pid) {
    // Implement Vnodes FD table display
        DIR *dir;
    struct dirent *entry;
    char proc_fd_path[MAX_PATH_LEN];

    printf("FD\tInode\n");
    printf("========================================\n");
    
    if(pid != -1 && kill(pid, 0) != -1){
        snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%d/fd", pid);
        dir = opendir(proc_fd_path);
        if (dir == NULL) {
            perror("Error opening directory\n");
            exit(EXIT_FAILURE);
        }


        while ((entry = readdir(dir)) != NULL) {

            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char fd_path[MAX_PATH_LEN];
                char filename[MAX_FILENAME_LEN];
                ssize_t readlink_size;

                snprintf(fd_path, MAX_PATH_LEN, "%s/%s", proc_fd_path, entry->d_name);
                readlink_size = readlink(fd_path, filename, MAX_FILENAME_LEN - 1);
                if (readlink_size != -1) {
                    // Get inode of the file
                        struct stat statbuf;
                        if (lstat(filename, &statbuf) != -1) {
                            printf("%d\t%lu\n", pid, statbuf.st_ino);
                        }
                } 
                else {
                    perror("Error reading link\n");
                }
            }
        }

        closedir(dir);
    }

    else if(pid==-1){
        // Implement composed table display
        ssize_t bufsize = 256;
        char linkname[bufsize];

        // Open the /proc directory
        dir = opendir("/proc");
        if (dir == NULL) {
            perror("Error opening /proc directory\n");
            exit(EXIT_FAILURE);
        }

        // Traverse each process directory
        while ((entry = readdir(dir)) != NULL) {
            // Skip non-process directories
            if (!isdigit(entry->d_name[0])) continue;

            int check_pid = atoi(entry->d_name);
            // check if we have permission to access this pid 
            if (kill(check_pid, 0) == -1) {
                continue; 
            }

            snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%s/fd/", entry->d_name);

            // Open the file descriptor directory of the process
            DIR *fd_dir = opendir(proc_fd_path);
            if (fd_dir != NULL) {
                // Traverse each file descriptor entry
                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    // Skip "." and ".." entries
                    if (strcmp(fd_entry->d_name, ".") == 0 || strcmp(fd_entry->d_name, "..") == 0)
                        continue;

                    // Construct the file descriptor path
                    char fd_path[MAX_PATH_LEN];
                    snprintf(fd_path, MAX_PATH_LEN, "%s%s", proc_fd_path, fd_entry->d_name);

                    // Read the symbolic link to get the file name
                    ssize_t len = readlink(fd_path, linkname, bufsize - 1);
                    if (len != -1) {
                        linkname[len] = '\0'; // Null-terminate the string

                        // Get inode of the file
                        struct stat statbuf;
                        if (lstat(linkname, &statbuf) != -1) {
                            printf("%s\t%lu\n", fd_entry->d_name, statbuf.st_ino);
                        }
                    }
                    else {
                        perror("Error reading link\n");
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    printf("========================================\n");
}

void display_composed_table(pid_t pid) {
    DIR *dir;
    struct dirent *entry;
    char proc_fd_path[MAX_PATH_LEN];

    printf("PID\tFD\tFilename\tInode\n");
    printf("========================================\n");
    
    if(pid != -1 && kill(pid, 0) != -1){
        snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%d/fd", pid);
        dir = opendir(proc_fd_path);
        if (dir == NULL) {
            perror("Error opening directory\n");
            exit(EXIT_FAILURE);
        }

        while ((entry = readdir(dir)) != NULL) {

            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                char fd_path[MAX_PATH_LEN];
                char filename[MAX_FILENAME_LEN];
                ssize_t readlink_size;

                snprintf(fd_path, MAX_PATH_LEN, "%s/%s", proc_fd_path, entry->d_name);
                readlink_size = readlink(fd_path, filename, MAX_FILENAME_LEN - 1);
                if (readlink_size != -1) {
                    // Get inode of the file
                        struct stat statbuf;
                        if (lstat(filename, &statbuf) != -1) {
                            printf("%d\t%s\t%s\t%lu\n", pid, entry->d_name, filename, statbuf.st_ino);
                        }
                } 
                else {
                    perror("Error reading link\n");
                }
            }
        }

        closedir(dir);
    }

    
    
    if (pid == -1){
        // Implement composed table display
        ssize_t bufsize = 256;
        char linkname[bufsize];

        // Open the /proc directory
        dir = opendir("/proc");
        if (dir == NULL) {
            perror("Error opening /proc directory\n");
            exit(EXIT_FAILURE);
        }

        // Traverse each process directory
        while ((entry = readdir(dir)) != NULL) {
            // Skip non-process directories
            if (!isdigit(entry->d_name[0])) continue;
            
            int check_pid = atoi(entry->d_name);
            // check if we have permission to access this pid 
            if (kill(check_pid, 0) == -1) {
                continue; 
            }

            snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%s/fd/", entry->d_name);

            // Open the file descriptor directory of the process
            DIR *fd_dir = opendir(proc_fd_path);
            if (fd_dir != NULL) {
                // Traverse each file descriptor entry
                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    // Skip "." and ".." entries
                    if (strcmp(fd_entry->d_name, ".") == 0 || strcmp(fd_entry->d_name, "..") == 0)
                        continue;

                    // Construct the file descriptor path
                    char fd_path[MAX_PATH_LEN];
                    snprintf(fd_path, MAX_PATH_LEN, "%s%s", proc_fd_path, fd_entry->d_name);

                    // Read the symbolic link to get the file name
                    ssize_t len = readlink(fd_path, linkname, bufsize - 1);
                    if (len != -1) {
                        linkname[len] = '\0'; // Null-terminate the string

                        // Get inode of the file
                        struct stat statbuf;
                        if (lstat(linkname, &statbuf) != -1) {
                            printf("%s\t%s\t%s\t%lu\n", entry->d_name, fd_entry->d_name, linkname, statbuf.st_ino);
                        }
                    }
                    else {
                        perror("Error reading link\n");
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }
    printf("========================================\n");
}

void flag_offending_processes(int threshold) {
    DIR *proc_dir;
    struct dirent *entry;

    // Open the /proc directory
    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("Error opening /proc directory");
        exit(EXIT_FAILURE);
    }

    printf("\nOffending processes (PID, FD):\n");

    // Iterate through each entry in the /proc directory
    while ((entry = readdir(proc_dir)) != NULL) {
        // Convert the entry name to a process ID
        pid_t pid = atoi(entry->d_name);

        // check if we have permission to access this pid 
        if (kill(pid, 0) == -1) {
            continue; 
        }

        if (pid > 0) {
            char proc_fd_path[MAX_PATH_LEN];
            DIR *proc_fd_dir;
            struct dirent *fd_entry;

            // Construct the path to the /proc/<pid>/fd directory
            snprintf(proc_fd_path, MAX_PATH_LEN, "/proc/%s/fd", entry->d_name);
            proc_fd_dir = opendir(proc_fd_path);

            if (proc_fd_dir != NULL) {
                // Check each file descriptor for the process
                while ((fd_entry = readdir(proc_fd_dir)) != NULL) {
                    if (strcmp(fd_entry->d_name, ".") != 0 && strcmp(fd_entry->d_name, "..") != 0) {
                        int fd = atoi(fd_entry->d_name);
                        if (fd > threshold) {
                            printf("%s (%d), ", entry->d_name, fd);
                        }
                    }
                }

                closedir(proc_fd_dir);
            } 
            //else {
            //    perror("Error opening process FD directory\n");
            //}
        }
    }
    closedir(proc_dir);
}

int isPid(char *string){
    int res = 1;
    for (int i=0; string[i]!='\0';i++){
        if (!isdigit(string[i])){
            res = 0;
        }
    }
    return res;
}

void save_composite_table_text(const char *filename, pid_t pid) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }

    // Redirect stdout to the file
    dup2(fileno(file), STDOUT_FILENO);

    // Display the composite table
    display_process_fd_table(pid);

    // Close the file
    fclose(file);
}

void save_composite_table_binary(const char *filename, pid_t pid) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }

    // Redirect stdout to the file
    dup2(fileno(file), STDOUT_FILENO);

    // Display the composite table
    display_process_fd_table(pid);

    // Close the file
    fclose(file);
}


void display_usage(){
    printf("Usage: ./program_name [PID] [--per-process] [--systemWide] [--Vnodes] [--composite] [--threshold=X]\n");
}