#include "employee.h"
#include "common.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>


static void add_customer(int sock) {
    char buf[BUFFER_SIZE];
    char path[100];
    snprintf(path, 100, "%s/customers.csv", DATA_DIR);

    int new_id = get_next_id_csv(path);

    send_message(sock, "Enter username: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    char username[50];
    strcpy(username, buf);

    send_message(sock, "Enter password: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    char password[50];
    strcpy(password, buf);

    send_message(sock, "Initial balance: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    double balance = atof(buf);

    FILE *fp = fopen(path, "a");
    if (!fp) {
        send_message(sock, "Error\n");
        return;
    }

    fprintf(fp, "%d,%s,%s,%.2f,1\n", new_id, username, password, balance);
    fclose(fp);

    snprintf(buf, BUFFER_SIZE, "Customer created! ID: %d\n", new_id);
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

static void view_assigned_loans(int sock, int eid) {
    char path[100];
    snprintf(path, 100, "%s/loans.csv", DATA_DIR);

    FILE *fp = fopen(path, "r");
    if (!fp) {
        send_message(sock, "No loans\n");
        return;
    }

    char line[300], buffer[400];
    send_message(sock, "\n=== Assigned Loans ===\n");

    fgets(line, sizeof(line), fp);  // Skip header

    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        int loan_id, customer_id, tenure;
        char loan_type[50], status[50], assigned_employee[50];
        double amount;

        trim_string(line);

        // Parse: loan_id,customer_id,amount,loan_type,tenure,status,assigned_employee
        if (sscanf(line, "%d,%d,%lf,%49[^,],%d,%49[^,],%49[^\n]",
                   &loan_id, &customer_id, &amount, loan_type, &tenure, status, assigned_employee) == 7) {
            trim_string(loan_type);
            trim_string(status);
            trim_string(assigned_employee);

            // Check if assigned to this employee
            char emp_id_str[20];
            snprintf(emp_id_str, 20, "%d", eid);

            if (strcmp(assigned_employee, emp_id_str) == 0) {
                snprintf(buffer, 400,
                        "Loan ID: %d | Customer: %d | Amount: %.2f | Type: %s | Tenure: %dy | Status: %s\n",
                        loan_id, customer_id, amount, loan_type, tenure, status);
                send_message(sock, buffer);
                count++;
            }
                   }
    }

    if (count == 0) {
        send_message(sock, "No loans assigned to you\n");
    }

    fclose(fp);
}

static void process_loan(int sock, int eid) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter loan ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int lid = atoi(buf);

    send_message(sock, "Approve (1) or Reject (0): ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int approve = atoi(buf);

    char path[100], temp_path[100];
    snprintf(path, 100, "%s/loans.csv", DATA_DIR);
    snprintf(temp_path, 100, "%s/loans.tmp", DATA_DIR);

    FILE *fp = fopen(path, "r");
    FILE *tmp = fopen(temp_path, "w");

    if (!fp || !tmp) {
        if (fp) fclose(fp);
        if (tmp) fclose(tmp);
        send_message(sock, "Error\n");
        return;
    }

    char line[300];
    int found = 0;
    int loan_customer_id = -1;
    double loan_amount = 0.0;

    fgets(line, sizeof(line), fp);
    fprintf(tmp, "loan_id,customer_id,amount,loan_type,tenure,status,assigned_employee\n");

    while (fgets(line, sizeof(line), fp)) {
        int loan_id, customer_id, tenure;
        char loan_type[50], status[50], assigned_employee[50];
        double amount;

        trim_string(line);

        // Parse: loan_id,customer_id,amount,loan_type,tenure,status,assigned_employee
        if (sscanf(line, "%d,%d,%lf,%49[^,],%d,%49[^,],%49[^\n]",
                   &loan_id, &customer_id, &amount, loan_type, &tenure, status, assigned_employee) == 7) {
            trim_string(loan_type);
            trim_string(status);
            trim_string(assigned_employee);

            if (loan_id == lid) {
                // Check if this loan is assigned to current employee
                char emp_id_str[20];
                snprintf(emp_id_str, 20, "%d", eid);

                // Debug: Print what we're comparing
                char debug[200];
                snprintf(debug, 200, "DEBUG: loan_id=%d, assigned='%s', current_emp='%s'\n",
                        loan_id, assigned_employee, emp_id_str);
                send_message(sock, debug);

                if (strcmp(assigned_employee, emp_id_str) == 0) {
                    strcpy(status, approve ? "approved" : "rejected");
                    found = 1;

                    if (approve) {
                        loan_customer_id = customer_id;
                        loan_amount = amount;
                    }
                }
            }
            fprintf(tmp, "%d,%d,%.2f,%s,%d,%s,%s\n",
                    loan_id, customer_id, amount, loan_type, tenure, status, assigned_employee);
        }
    }

    fclose(fp);
    fclose(tmp);

    if (!found) {
        remove(temp_path);
        send_message(sock, "Loan not found or not assigned to you\n");
        return;
    }

    rename(temp_path, path);

    // If loan approved, credit amount to customer's account
    if (approve && loan_customer_id != -1) {
        // Credit logic here (same as before)
        char cust_path[100], cust_temp[100];
        snprintf(cust_path, 100, "%s/customers.csv", DATA_DIR);
        snprintf(cust_temp, 100, "%s/customers.tmp", DATA_DIR);

        FILE *cust_fp = fopen(cust_path, "r");
        FILE *cust_tmp = fopen(cust_temp, "w");

        if (!cust_fp || !cust_tmp) {
            if (cust_fp) fclose(cust_fp);
            if (cust_tmp) fclose(cust_tmp);
            send_message(sock, "Loan processed but couldn't credit amount\n");
            return;
        }

        char cust_line[256];
        double new_balance = 0;

        fgets(cust_line, sizeof(cust_line), cust_fp);
        fprintf(cust_tmp, "id,username,password,balance,active\n");

        while (fgets(cust_line, sizeof(cust_line), cust_fp)) {
            int id, active;
            char user[50], pass[50];
            double balance;

            trim_string(cust_line);

            if (sscanf(cust_line, "%d,%49[^,],%49[^,],%lf,%d",
                       &id, user, pass, &balance, &active) == 5) {
                trim_string(user);
                trim_string(pass);

                if (id == loan_customer_id) {
                    balance += loan_amount;
                    new_balance = balance;
                }
                fprintf(cust_tmp, "%d,%s,%s,%.2f,%d\n", id, user, pass, balance, active);
            }
        }

        fclose(cust_fp);
        fclose(cust_tmp);
        rename(cust_temp, cust_path);

        // Add transaction
        FILE *trans_fp = fopen(DATA_DIR "/transactions.csv", "a");
        if (trans_fp) {
            time_t now = time(NULL);
            char timestamp[50];
            strftime(timestamp, 50, "%Y-%m-%d %H:%M:%S", localtime(&now));
            fprintf(trans_fp, "%d,LOAN_CREDIT,%.2f,%.2f,%s\n",
                    loan_customer_id, loan_amount, new_balance, timestamp);
            fclose(trans_fp);
        }

        snprintf(buf, BUFFER_SIZE, "Loan approved! Amount %.2f credited to customer's account\n", loan_amount);
        send_message(sock, buf);
    } else {
        send_message(sock, "Loan rejected\n");
    }
}


static void view_customer_transactions(int sock) {
    char buf[BUFFER_SIZE];

    send_message(sock, "Enter customer ID: ");
    if (!read_input(sock, buf, BUFFER_SIZE)) return;
    int cid = atoi(buf);

    FILE *fp = fopen(DATA_DIR "/transactions.csv", "r");
    if (!fp) {
        send_message(sock, "No transactions\n");
        return;
    }

    char line[256], buffer[200];
    send_message(sock, "\n=== Customer Transaction History (Passbook) ===\n");

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
        send_message(sock, "No transactions found for this customer\n");
    }

    fclose(fp);
}

static void change_password(int sock, int eid) {
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
    snprintf(path, 100, "%s/employees.csv", DATA_DIR);

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
    FILE *tmp = fopen(DATA_DIR "/employees.tmp", "w");

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
    rename(DATA_DIR "/employees.tmp", path);
    unlock_file(fd);
    close(fd);

    send_message(sock, found ? "Password changed successfully\n" : "Incorrect password\n");
}

void handle_employee(int sock, int eid) {
    char buffer[BUFFER_SIZE];

    while (1) {
        send_message(sock,
            "\n=== Employee Menu ===\n"
            "1. Add New Customer\n"
            "2. Modify Customer Details\n"
            "3. Process Loan Applications\n"
            "4. View Assigned Loan Applications\n"
            "5. View Customer Transactions (Passbook)\n"
            "6. Change Password\n"
            "7. Logout\n"
            "Choice: ");

        if (!read_input(sock, buffer, BUFFER_SIZE)) break;
        int choice = atoi(buffer);

        switch (choice) {
            case 1: add_customer(sock); break;
            case 2: modify_customer(sock); break;
            case 3: process_loan(sock, eid); break;
            case 4: view_assigned_loans(sock, eid); break;
            case 5: view_customer_transactions(sock); break;
            case 6: change_password(sock, eid); break;
            case 7: return;
            default: send_message(sock, "Invalid choice\n");
        }
    }
}
