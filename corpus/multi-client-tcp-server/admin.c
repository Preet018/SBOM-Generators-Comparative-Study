#include "admin.h"
#include "common.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static void add_employee(int sock) {
    char buf[BUFFER_SIZE];
    char path[100];
    snprintf(path, 100, "%s/employees.csv", DATA_DIR);

    int new_id = get_next_id_csv(path);

    send_message(sock, "Enter username: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    char username[50];
    strcpy(username, buf);

    send_message(sock, "Enter password: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    char password[50];
    strcpy(password, buf);

    FILE *fp = fopen(path, "a");
    if (!fp) {
        send_message(sock, "Error\n");
        return;
    }

    fprintf(fp, "%d,%s,%s\n", new_id, username, password);
    fclose(fp);

    snprintf(buf, BUFFER_SIZE, "Employee created! ID: %d\n", new_id);
    send_message(sock, buf);
}

static void modify_customer(int sock) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter customer ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int cid = atoi(buf);

    char path[100], temp_path[100];
    snprintf(path, 100, "%s/customers.csv", DATA_DIR);
    snprintf(temp_path, 100, "%s/customers.tmp", DATA_DIR);

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        send_message(sock, "Error opening file\n");
        return;
    }

    if (lock_file(fd, F_WRLCK) == -1) {
        close(fd);
        send_message(sock, "Error acquiring lock\n");
        return;
    }

    FILE *fp = fdopen(dup(fd), "r");
    FILE *tmp = fopen(temp_path, "w");

    if (!fp || !tmp) {
        if (fp) fclose(fp);
        if (tmp) fclose(tmp);
        unlock_file(fd);
        close(fd);
        send_message(sock, "Error\n");
        return;
    }

    char line[256];
    int found = 0;

    fgets(line, sizeof(line), fp);
    fprintf(tmp, "id,username,password,balance,active\n");

    while (fgets(line, sizeof(line), fp)) {
        int id, active;
        char user[50], pass[50];
        double balance;

        trim_string(line);

        if (sscanf(line, "%d,%49[^,],%49[^,],%lf,%d", &id, user, pass, &balance, &active) == 5) {
            trim_string(user);
            trim_string(pass);

            if (id == cid) {
                found = 1;

                send_message(sock, "New username (- to skip): ");
                if (read_input(sock, buf, BUFFER_SIZE) && buf[0] != '-') {
                    strcpy(user, buf);
                }

                send_message(sock, "New password (- to skip): ");
                if (read_input(sock, buf, BUFFER_SIZE) && buf[0] != '-') {
                    strcpy(pass, buf);
                }
            }
            fprintf(tmp, "%d,%s,%s,%.2f,%d\n", id, user, pass, balance, active);
        }
    }

    fclose(fp);
    fclose(tmp);
    rename(temp_path, path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Customer updated\n" : "Customer not found\n");
}

static void modify_employee(int sock) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter employee ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int eid = atoi(buf);

    char path[100], temp_path[100];
    snprintf(path, 100, "%s/employees.csv", DATA_DIR);
    snprintf(temp_path, 100, "%s/employees.tmp", DATA_DIR);

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        send_message(sock, "Error opening file\n");
        return;
    }

    if (lock_file(fd, F_WRLCK) == -1) {
        close(fd);
        send_message(sock, "Error acquiring lock\n");
        return;
    }

    FILE *fp = fdopen(dup(fd), "r");
    FILE *tmp = fopen(temp_path, "w");

    if (!fp || !tmp) {
        if (fp) fclose(fp);
        if (tmp) fclose(tmp);
        unlock_file(fd);
        close(fd);
        send_message(sock, "Error\n");
        return;
    }

    char line[256];
    int found = 0;

    fgets(line, sizeof(line), fp);
    fprintf(tmp, "id,username,password\n");

    while (fgets(line, sizeof(line), fp)) {
        int id;
        char user[50], pass[50];

        trim_string(line);

        if (sscanf(line, "%d,%49[^,],%49[^\n]", &id, user, pass) == 3) {
            trim_string(user);
            trim_string(pass);

            if (id == eid) {
                found = 1;

                send_message(sock, "New username (- to skip): ");
                if (read_input(sock, buf, BUFFER_SIZE) && buf[0] != '-') {
                    strcpy(user, buf);
                }

                send_message(sock, "New password (- to skip): ");
                if (read_input(sock, buf, BUFFER_SIZE) && buf[0] != '-') {
                    strcpy(pass, buf);
                }
            }
            fprintf(tmp, "%d,%s,%s\n", id, user, pass);
        }
    }

    fclose(fp);
    fclose(tmp);
    rename(temp_path, path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Employee updated\n" : "Employee not found\n");
}

static void manage_user_roles(int sock) {
    char buf[BUFFER_SIZE];

    send_message(sock,
        "\n=== Manage User Roles ===\n"
        "1. Promote Employee to Manager\n"
        "2. Demote Manager to Employee\n"
        "Choice: ");

    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int choice = atoi(buf);

    if (choice == 1) {
        send_message(sock, "Enter employee ID to promote: ");
        if (!read_input(sock, buf, BUFFER_SIZE)) return;
        int eid = atoi(buf);

        FILE *emp_fp = fopen(DATA_DIR "/employees.csv", "r");
        if (!emp_fp) {
            send_message(sock, "Error reading employees\n");
            return;
        }

        char line[256];
        int found = 0;
        char username[50], password[50];

        fgets(line, sizeof(line), emp_fp);

        while (fgets(line, sizeof(line), emp_fp)) {
            int id;
            char user[50], pass[50];

            trim_string(line);

            if (sscanf(line, "%d,%49[^,],%49[^\n]", &id, user, pass) == 3) {
                trim_string(user);
                trim_string(pass);

                if (id == eid) {
                    found = 1;
                    strcpy(username, user);
                    strcpy(password, pass);
                    break;
                }
            }
        }
        fclose(emp_fp);

        if (!found) {
            send_message(sock, "Employee not found\n");
            return;
        }

        int new_mid = get_next_id_csv(DATA_DIR "/managers.csv");
        FILE *mgr_fp = fopen(DATA_DIR "/managers.csv", "a");
        if (mgr_fp) {
            fprintf(mgr_fp, "%d,%s,%s\n", new_mid, username, password);
            fclose(mgr_fp);
        }

        FILE *emp_read = fopen(DATA_DIR "/employees.csv", "r");
        FILE *emp_write = fopen(DATA_DIR "/employees.tmp", "w");

        fgets(line, sizeof(line), emp_read);
        fprintf(emp_write, "id,username,password\n");

        while (fgets(line, sizeof(line), emp_read)) {
            int id;

            trim_string(line);

            if (sscanf(line, "%d,", &id) == 1 && id != eid) {
                fprintf(emp_write, "%s\n", line);
            }
        }

        fclose(emp_read);
        fclose(emp_write);
        rename(DATA_DIR "/employees.tmp", DATA_DIR "/employees.csv");

        send_message(sock, "Employee promoted to Manager successfully\n");

    } else if (choice == 2) {
        send_message(sock, "Enter manager ID to demote: ");
        if (!read_input(sock, buf, BUFFER_SIZE)) return;
        int mid = atoi(buf);

        FILE *mgr_fp = fopen(DATA_DIR "/managers.csv", "r");
        if (!mgr_fp) {
            send_message(sock, "Error reading managers\n");
            return;
        }

        char line[256];
        int found = 0;
        char username[50], password[50];

        fgets(line, sizeof(line), mgr_fp);

        while (fgets(line, sizeof(line), mgr_fp)) {
            int id;
            char user[50], pass[50];

            trim_string(line);

            if (sscanf(line, "%d,%49[^,],%49[^\n]", &id, user, pass) == 3) {
                trim_string(user);
                trim_string(pass);

                if (id == mid) {
                    found = 1;
                    strcpy(username, user);
                    strcpy(password, pass);
                    break;
                }
            }
        }
        fclose(mgr_fp);

        if (!found) {
            send_message(sock, "Manager not found\n");
            return;
        }

        int new_eid = get_next_id_csv(DATA_DIR "/employees.csv");
        FILE *emp_fp = fopen(DATA_DIR "/employees.csv", "a");
        if (emp_fp) {
            fprintf(emp_fp, "%d,%s,%s\n", new_eid, username, password);
            fclose(emp_fp);
        }

        FILE *mgr_read = fopen(DATA_DIR "/managers.csv", "r");
        FILE *mgr_write = fopen(DATA_DIR "/managers.tmp", "w");

        fgets(line, sizeof(line), mgr_read);
        fprintf(mgr_write, "id,username,password\n");

        while (fgets(line, sizeof(line), mgr_read)) {
            int id;

            trim_string(line);

            if (sscanf(line, "%d,", &id) == 1 && id != mid) {
                fprintf(mgr_write, "%s\n", line);
            }
        }

        fclose(mgr_read);
        fclose(mgr_write);
        rename(DATA_DIR "/managers.tmp", DATA_DIR "/managers.csv");

        send_message(sock, "Manager demoted to Employee successfully\n");
    }
}

static void change_password(int sock, int aid) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter current password: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    char old_pass[50];
    strcpy(old_pass, buf);

    send_message(sock, "Enter new password: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    char new_pass[50];
    strcpy(new_pass, buf);

    char path[100];
    snprintf(path, 100, "%s/admins.csv", DATA_DIR);

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        send_message(sock, "Error opening file\n");
        return;
    }

    if (lock_file(fd, F_WRLCK) == -1) {
        close(fd);
        send_message(sock, "Error acquiring lock\n");
        return;
    }

    FILE *fp = fdopen(dup(fd), "r");
    FILE *tmp = fopen(DATA_DIR "/admins.tmp", "w");

    if (!fp || !tmp) {
        if (fp) fclose(fp);
        if (tmp) fclose(tmp);
        unlock_file(fd);
        close(fd);
        send_message(sock, "Error\n");
        return;
    }

    char line[256];
    int found = 0;

    fgets(line, sizeof(line), fp);
    fprintf(tmp, "id,username,password\n");

    while (fgets(line, sizeof(line), fp)) {
        int id;
        char user[50], pass[50];

        trim_string(line);

        if (sscanf(line, "%d,%49[^,],%49[^\n]", &id, user, pass) == 3) {
            trim_string(user);
            trim_string(pass);

            if (id == aid) {
                if (strcmp(pass, old_pass) == 0) {
                    strcpy(pass, new_pass);
                    found = 1;
                }
            }
            fprintf(tmp, "%d,%s,%s\n", id, user, pass);
        }
    }

    fclose(fp);
    fclose(tmp);
    rename(DATA_DIR "/admins.tmp", path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Password changed successfully\n" : "Incorrect password\n");
}

void handle_admin(int sock, int aid) {
    char buffer[BUFFER_SIZE];

    while (1) {
        send_message(sock,
            "\n=== Admin Menu ===\n"
            "1. Add New Bank Employee\n"
            "2. Modify Customer Details\n"
            "3. Modify Employee Details\n"
            "4. Manage User Roles\n"
            "5. Change Password\n"
            "6. Logout\n"
            "Choice: ");

        if (!read_input(sock, buffer, BUFFER_SIZE)) break;
        int choice = atoi(buffer);

        switch (choice) {
            case 1: add_employee(sock); break;
            case 2: modify_customer(sock); break;
            case 3: modify_employee(sock); break;
            case 4: manage_user_roles(sock); break;
            case 5: change_password(sock, aid); break;
            case 6: return;
            default: send_message(sock, "Invalid choice\n");
        }
    }
}
