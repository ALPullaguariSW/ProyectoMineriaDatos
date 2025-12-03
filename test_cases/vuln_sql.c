#include <stdio.h>
#include <string.h>

void get_user_data(char *user_id) {
    char query[256];
    // VULNERABLE: Direct string concatenation allows SQL Injection
    sprintf(query, "SELECT * FROM users WHERE id = '%s'", user_id);
    execute_query(query);
}
