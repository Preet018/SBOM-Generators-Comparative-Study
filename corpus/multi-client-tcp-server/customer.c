#include "customer.h"
#include "common.h"
#include "utils.h"
#include "session_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

static void add_transaction(int cid, const char *type, double amt, double bal) {
    FILE *fp = fopen(DATA_DIR "/transactions.csv", "a");
    if (!fp) return;

    time_t now = time(NULL);
    char timestamp[50];
    strftime(timestamp, 50, "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(fp, "%d,%s,%.2f,%.2f,%s\n", cid, type, amt, bal, timestamp);
    fclose(fp);
}

static void view_balance(int sock, int cid) {
    FILE *fp = fopen(DATA_DIR "/customers.csv", "r");
    if (!fp) { send_message(sock, "Error\n"); return; }

    char line[256], msg[100];
    fgets(line, sizeof(line), fp); //Reads Header and dont process it and goes to next line

    while (fgets(line, sizeof(line), fp)) { //Returns Null at end of all line
        int id, active;
        char user[50], pass[50];
        double balance;

        trim_string(line);

        if (sscanf(line, "%d,%49[^,],%49[^,],%lf,%d", &id, user, pass, &balance, &active) == 5) {
            if (id == cid) {
                snprintf(msg, 100, "Balance: %.2f\n", balance);
                send_message(sock, msg);
                break;
            }
        }
    }
    fclose(fp);
}

static void update_balance(int sock, int cid, double amount, int is_deposit) {
    //Build file path
    char path[100];
    snprintf(path, 100, "%s/customers.csv", DATA_DIR);

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        send_message(sock, "Error opening file\n");
        return;
    }
    //Need file descriptor (fd) for lock_file() function
    //fopen() returns FILE* pointer, not file descriptor
    if (lock_file(fd, F_WRLCK) == -1) {
        close(fd);
        send_message(sock, "Error acquiring lock\n");
        return;
    }

    FILE *fp = fdopen(dup(fd), "r");

    //creates temp file because we cant directly write into csv
    FILE *tmp = fopen(DATA_DIR "/customers.tmp", "w");


    if (!fp || !tmp) {
        if (fp) fclose(fp);
        if (tmp) fclose(tmp);
        unlock_file(fd);
        close(fd);
        send_message(sock, "Error\n");
        return;
    }

    char line[256], msg[BUFFER_SIZE];
    int found = 0;
    double new_balance = 0;

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
                if (is_deposit) {
                    balance += amount;
                    new_balance = balance;
                    found = 1;
                } else {
                    if (balance >= amount) {
                        balance -= amount;
                        new_balance = balance;
                        found = 1;
                    } else {
                        fclose(fp);
                        fclose(tmp);
                        remove(DATA_DIR "/customers.tmp");
                        unlock_file(fd);
                        close(fd);
                        send_message(sock, "Insufficient balance\n");
                        return;
                    }
                }
            }
            fprintf(tmp, "%d,%s,%s,%.2f,%d\n", id, user, pass, balance, active);
        }
    }

    fclose(fp);
    fclose(tmp);
    rename(DATA_DIR "/customers.tmp", path);
    unlock_file(fd);
    close(fd);

    if (found) {
        add_transaction(cid, is_deposit ? "DEPOSIT" : "WITHDRAWAL", amount, new_balance);
        snprintf(msg, BUFFER_SIZE, "Success! New balance: %.2f\n", new_balance);
        send_message(sock, msg);
    } else {
        send_message(sock, "Error\n");
    }
}

static void transfer_funds(int sock, int cid) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter recipient ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int recipient_id = atoi(buf);

    send_message(sock, "Enter amount: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    double amount = atof(buf);

    if (amount <= 0 || recipient_id == cid) {
        send_message(sock, "Invalid transfer\n");
        return;
    }

    char path[100];
    snprintf(path, 100, "%s/customers.csv", DATA_DIR);

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
    FILE *tmp = fopen(DATA_DIR "/customers.tmp", "w");

    if (!fp || !tmp) {
        if (fp) fclose(fp);
        if (tmp) fclose(tmp);
        unlock_file(fd);
        close(fd);
        send_message(sock, "Error\n");
        return;
    }

    char line[256];
    int sender_found = 0, recipient_found = 0;
    double sender_balance = 0, recipient_balance = 0;

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
                sender_found = 1;
                if (balance < amount) {
                    fclose(fp);
                    fclose(tmp);
                    remove(DATA_DIR "/customers.tmp");
                    unlock_file(fd);
                    close(fd);
                    send_message(sock, "Insufficient balance\n");
                    return;
                }
                balance -= amount;
                sender_balance = balance;
            } else if (id == recipient_id) {
                recipient_found = 1;
                balance += amount;
                recipient_balance = balance;
            }
            fprintf(tmp, "%d,%s,%s,%.2f,%d\n", id, user, pass, balance, active);
        }
    }

    fclose(fp);
    fclose(tmp);

    if (sender_found && recipient_found) {
        rename(DATA_DIR "/customers.tmp", path);
        unlock_file(fd);
        close(fd);

        add_transaction(cid, "TRANSFER_OUT", amount, sender_balance);
        add_transaction(recipient_id, "TRANSFER_IN", amount, recipient_balance);

        snprintf(buf, BUFFER_SIZE, "Transfer successful! Balance: %.2f\n", sender_balance);
        send_message(sock, buf);
    } else {
        remove(DATA_DIR "/customers.tmp");
        unlock_file(fd);
        close(fd);
        send_message(sock, "Invalid accounts\n");
    }
}

// NEW: Enhanced loan application with type and tenure
static void apply_loan(int sock, int cid) {
    char buf[BUFFER_SIZE];

    send_message(sock, "=== Welcome to Loan Portal ===\n");

    send_message(sock, "Enter loan amount: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    double amount = atof(buf);

    if (amount <= 0) {
        send_message(sock, "Invalid amount\n");
        return;
    }

    send_message(sock, "Enter loan type (Personal/Home/Education): ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    char loan_type[50];
    strcpy(loan_type, buf);
    trim_string(loan_type);

    send_message(sock, "Enter tenure (years): ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int tenure = atoi(buf);

    if (tenure <= 0) {
        send_message(sock, "Invalid tenure\n");
        return;
    }

    char path[100];
    snprintf(path, 100, "%s/loans.csv", DATA_DIR);

    int loan_id = get_next_id_csv(path);

    FILE *fp = fopen(path, "a");
    if (!fp) {
        send_message(sock, "Error submitting loan\n");
        return;
    }

    // Format: loan_id,customer_id,amount,loan_type,tenure,status,assigned_employee
    fprintf(fp, "%d,%d,%.2f,%s,%d,pending,unassigned\n", loan_id, cid, amount, loan_type, tenure);
    fclose(fp);

    snprintf(buf, BUFFER_SIZE, "Loan application successful! Loan ID: %d\n", loan_id);
    send_message(sock, buf);
}

// NEW: Check loan status
static void check_loan_status(int sock, int cid) {
    FILE *fp = fopen(DATA_DIR "/loans.csv", "r");
    if (!fp) {
        send_message(sock, "No loans found\n");
        return;
    }

    char line[300], buffer[400];
    send_message(sock, "\n=== Your Loan Applications ===\n");
    send_message(sock, "Loan ID | Amount   | Type       | Tenure | Status    | Assigned To\n");
    send_message(sock, "---------------------------------------------------------------\n");

    fgets(line, sizeof(line), fp); // header

    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        int loan_id, customer_id, tenure;
        char loan_type[50], status[20], assigned_emp[50];
        double amount;

        trim_string(line);

        // Parse: loan_id,customer_id,amount,loan_type,tenure,status,assigned_employee
        if (sscanf(line, "%d,%d,%lf,%49[^,],%d,%19[^,],%49[^\n]",
                   &loan_id, &customer_id, &amount, loan_type, &tenure, status, assigned_emp) == 7) {
            trim_string(loan_type);
            trim_string(status);
            trim_string(assigned_emp);

            if (customer_id == cid) {
                snprintf(buffer, 400, "%7d | %8.2f | %-10s | %6d | %-9s | %-12s\n",
                        loan_id, amount, loan_type, tenure, status, assigned_emp);
                send_message(sock, buffer);
                count++;
            }
        }
    }

    if (count == 0) {
        send_message(sock, "No loan applications found\n");
    }

    fclose(fp);
}

static void change_password(int sock, int cid) {
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
    snprintf(path, 100, "%s/customers.csv", DATA_DIR);

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
    FILE *tmp = fopen(DATA_DIR "/customers.tmp", "w");

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
                if (strcmp(pass, old_pass) == 0) {
                    strcpy(pass, new_pass);
                    found = 1;
                }
            }
            fprintf(tmp, "%d,%s,%s,%.2f,%d\n", id, user, pass, balance, active);
        }
    }

    fclose(fp);
    fclose(tmp);
    rename(DATA_DIR "/customers.tmp", path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Password changed successfully\n" : "Incorrect password\n");
}

static void add_feedback(int sock, int cid) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter feedback message: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;

    char path[100];
    snprintf(path, 100, "%s/feedback.csv", DATA_DIR);

    int feedback_id = get_next_id_csv(path);

    FILE *fp = fopen(path, "a");
    if (!fp) return;

    fprintf(fp, "%d,%d,%s,0\n", feedback_id, cid, buf);
    fclose(fp);

    send_message(sock, "Feedback submitted successfully\n");
}

static void view_transactions(int sock, int cid) {
    FILE *fp = fopen(DATA_DIR "/transactions.csv", "r");
    if (!fp) { send_message(sock, "No transactions\n"); return; }

    char line[256], buffer[200];
    send_message(sock, "\n=== Transaction History ===\n");

    fgets(line, sizeof(line), fp);

    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        int customer_id;
        char type[20], timestamp[50];
        double amount, balance_after;

        trim_string(line);

        if (sscanf(line, "%d,%19[^,],%lf,%lf,%49[^\n]",
                   &customer_id, type, &amount, &balance_after, timestamp) == 5) {
            if (customer_id == cid) {
                snprintf(buffer, 200, "%s: %.2f | Balance: %.2f | %s\n",
                        type, amount, balance_after, timestamp);
                send_message(sock, buffer);
                count++;
            }
        }
    }

    if (count == 0) {
        send_message(sock, "No transactions found\n");
    }

    fclose(fp);
}

void handle_customer(int sock, int cid) {
    char buffer[BUFFER_SIZE];

    while (1) {
        send_message(sock,
            "\n=== Customer Menu ===\n"
            "1. View Account Balance\n"
            "2. Deposit Money\n"
            "3. Withdraw Money\n"
            "4. Transfer Funds\n"
            "5. Apply for a Loan\n"
            "6. Check Loan Status\n"
            "7. Change Password\n"
            "8. Add Feedback\n"
            "9. View Transaction History\n"
            "10. Logout\n"
            "Choice: ");

        if (!read_input(sock, buffer, BUFFER_SIZE)) break;
        int choice = atoi(buffer);

        switch (choice) {
            case 1: view_balance(sock, cid); break;
            case 2:
                send_message(sock, "Enter amount: ");
                if (read_input(sock, buffer, BUFFER_SIZE)) {
                    update_balance(sock, cid, atof(buffer), 1);
                }
                break;
            case 3:
                send_message(sock, "Enter amount: ");
                if (read_input(sock, buffer, BUFFER_SIZE)) {
                    update_balance(sock, cid, atof(buffer), 0);
                }
                break;
            case 4: transfer_funds(sock, cid); break;
            case 5: apply_loan(sock, cid); break;
            case 6: check_loan_status(sock, cid); break;
            case 7: change_password(sock, cid); break;
            case 8: add_feedback(sock, cid); break;
            case 9: view_transactions(sock, cid); break;
            case 10: return;
            default: send_message(sock, "Invalid choice\n");
        }
    }
}
