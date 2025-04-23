cmake_minimum_required(VERSION 3.16)

project(LR1_Kalashnikova VERSION 0.1 LANGUAGES CXX)

# Стандарт C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Автоматизация для Qt
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Поддержка Qt 6 или 5
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

# OpenSSL
set(OPENSSL_ROOT_DIR "C:/OpenSSL-Win64")
find_package(OpenSSL REQUIRED)
if (NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Проверьте путь: ${OPENSSL_ROOT_DIR}")
endif()

# Источники GUI-программы
set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)

# Сборка GUI-программы LR1_Kalashnikova
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(LR1_Kalashnikova
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        credentials.json
    )
else()
    if(ANDROID)
        add_library(LR1_Kalashnikova SHARED ${PROJECT_SOURCES})
    else()
        add_executable(LR1_Kalashnikova ${PROJECT_SOURCES})
    endif()
endif()

# Линковка с Qt и OpenSSL
target_include_directories(LR1_Kalashnikova PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(LR1_Kalashnikova PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Сборка protector.exe
add_executable(protector
    protector.cpp
)
target_link_libraries(protector PRIVATE kernel32)

# Для Windows: консольный режим
if (WIN32)
    set_target_properties(protector PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )
endif()

# Копирование credentials.json в папку bin
configure_file(${CMAKE_SOURCE_DIR}/credentials.json ${CMAKE_BINARY_DIR}/bin/credentials.json COPYONLY)

# Windeployqt для Qt библиотек
if (WIN32)
    set(WINDEPLOYQT_EXECUTABLE "C:/Qt/6.8.2/msvc2022_64/bin/windeployqt.exe")
    if (EXISTS ${WINDEPLOYQT_EXECUTABLE})
        add_custom_command(TARGET LR1_Kalashnikova POST_BUILD
            COMMAND ${WINDEPLOYQT_EXECUTABLE} $<TARGET_FILE:LR1_Kalashnikova>
            COMMENT "Копирование Qt-библиотек с помощью windeployqt..."
        )
    else()
        message(WARNING "windeployqt не найден по пути ${WINDEPLOYQT_EXECUTABLE}")
    endif()

    # OpenSSL DLLs
    set(OPENSSL_DLL_PATH "C:/Qt/Tools/OpenSSLv3/Win_x64/bin")
    set(OPENSSL_DLLS
        "${OPENSSL_DLL_PATH}/libcrypto-3-x64.dll"
        "${OPENSSL_DLL_PATH}/libssl-3-x64.dll"
    )

    foreach(DLL ${OPENSSL_DLLS})
        if (EXISTS ${DLL})
            add_custom_command(TARGET LR1_Kalashnikova POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${DLL}
                $<TARGET_FILE_DIR:LR1_Kalashnikova>
                COMMENT "Копирование ${DLL}..."
            )
        else()
            message(WARNING "${DLL} не найден. Скопируйте вручную.")
        endif()
    endforeach()
endif()

# Настройка путей вывода
set_target_properties(LR1_Kalashnikova protector PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Установка
include(GNUInstallDirs)
install(TARGETS LR1_Kalashnikova protector
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Финализация для Qt6
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(LR1_Kalashnikova)
endif()
