cmake_minimum_required(VERSION 3.10)
project(BankingSystem C)

set(CMAKE_C_STANDARD 11)

add_executable(server
        server.c
        auth.c
        customer.c
        employee.c
        manager.c
        admin.c
        utils.c
        session_manager.c
)
target_link_libraries(server pthread)

add_executable(client
        client.c
)
