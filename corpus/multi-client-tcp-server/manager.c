#include "manager.h"
#include "common.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static void activate_account(int sock) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter customer ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int cid = atoi(buf);

    send_message(sock, "Activate (1) or Deactivate (0): ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int activate = atoi(buf);

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
        int id, active_status;
        char user[50], pass[50];
        double balance;

        trim_string(line);

        if (sscanf(line, "%d,%49[^,],%49[^,],%lf,%d", &id, user, pass, &balance, &active_status) == 5) {
            trim_string(user);
            trim_string(pass);

            if (id == cid) {
                active_status = activate;
                found = 1;
            }
            fprintf(tmp, "%d,%s,%s,%.2f,%d\n", id, user, pass, balance, active_status);
        }
    }

    fclose(fp);
    fclose(tmp);
    rename(temp_path, path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Account updated\n" : "Account not found\n");
}

static void assign_loan(int sock) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter loan ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int lid = atoi(buf);

    send_message(sock, "Enter employee ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int eid = atoi(buf);

    char path[100], temp_path[100];
    snprintf(path, 100, "%s/loans.csv", DATA_DIR);
    snprintf(temp_path, 100, "%s/loans.tmp", DATA_DIR);

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

    char line[300];
    int found = 0;

    fgets(line, sizeof(line), fp);
    // Write correct header with 7 columns
    fprintf(tmp, "loan_id,customer_id,amount,loan_type,tenure,status,assigned_employee\n");

    while (fgets(line, sizeof(line), fp)) {
        int loan_id, customer_id, tenure;
        char loan_type[50], status[50], assigned_employee[50];
        double amount;

        trim_string(line);

        // Parse all 7 fields
        if (sscanf(line, "%d,%d,%lf,%49[^,],%d,%49[^,],%49[^\n]",
                   &loan_id, &customer_id, &amount, loan_type, &tenure, status, assigned_employee) == 7) {
            trim_string(loan_type);
            trim_string(status);
            trim_string(assigned_employee);

            if (loan_id == lid) {
                snprintf(assigned_employee, 50, "%d", eid);
                found = 1;
            }

            // Write all 7 fields in correct order
            fprintf(tmp, "%d,%d,%.2f,%s,%d,%s,%s\n",
                    loan_id, customer_id, amount, loan_type, tenure, status, assigned_employee);
        }
    }

    fclose(fp);
    fclose(tmp);
    rename(temp_path, path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Loan assigned\n" : "Loan not found\n");
}


static void view_feedback(int sock) {
    FILE *fp = fopen(DATA_DIR "/feedback.csv", "r");
    if (!fp) {
        send_message(sock, "No feedback available\n");
        return;
    }

    char line[300], buffer[400];
    send_message(sock, "\n=== Customer Feedback ===\n");

    fgets(line, sizeof(line), fp);

    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        int feedback_id, customer_id, reviewed;
        char message[256];

        trim_string(line);

        if (sscanf(line, "%d,%d,%255[^,],%d", &feedback_id, &customer_id, message, &reviewed) == 4) {
            trim_string(message);
            snprintf(buffer, 400, "ID: %d | Customer: %d | Message: %s | Reviewed: %s\n",
                    feedback_id, customer_id, message, reviewed ? "Yes" : "No");
            send_message(sock, buffer);
            count++;
        }
    }

    if (count == 0) {
        send_message(sock, "No feedback available\n");
    }

    fclose(fp);
}

static void change_password(int sock, int mid) {
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
    snprintf(path, 100, "%s/managers.csv", DATA_DIR);

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
    FILE *tmp = fopen(DATA_DIR "/managers.tmp", "w");

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

            if (id == mid) {
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
    rename(DATA_DIR "/managers.tmp", path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Password changed successfully\n" : "Incorrect password\n");
}

void handle_manager(int sock, int mid) {
    char buffer[BUFFER_SIZE];

    while (1) {
        send_message(sock,
            "\n=== Manager Menu ===\n"
            "1. Activate/Deactivate Customer Accounts\n"
            "2. Assign Loan Application Processes to Employees\n"
            "3. Review Customer Feedback\n"
            "4. Change Password\n"
            "5. Logout\n"
            "Choice: ");

        if (!read_input(sock, buffer, BUFFER_SIZE)) break;
        int choice = atoi(buffer);

        switch (choice) {
            case 1: activate_account(sock); break;
            case 2: assign_loan(sock); break;
            case 3: view_feedback(sock); break;
            case 4: change_password(sock, mid); break;
            case 5: return;
            default: send_message(sock, "Invalid choice\n");
        }
    }
}
