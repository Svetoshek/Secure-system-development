#define UNICODE
#include <windows.h>
#include <iostream>


int main() {
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };

    // Создаём изменяемый буфер для командной строки
    wchar_t commandLine[256] = { 0 }; // Инициализируем нули
    wcscpy_s(commandLine, L"LR1_Kalashnikova.exe --protector");

    // Запуск процесса
    BOOL success = CreateProcessW(
        L"LR1_Kalashnikova.exe",
        commandLine,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
        );

    if (!success) {
        std::cerr << "Failed to start LR1_Kalashnikova.exe: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Successfully started LR1_Kalashnikova.exe with PID: " << pi.dwProcessId << std::endl;

    // Подключение как отладчик
    success = DebugActiveProcess(pi.dwProcessId);
    if (!success) {
        std::cerr << "Failed to attach as debugger: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    // Цикл обработки отладочных событий
    DEBUG_EVENT debugEvent = { 0 };
    while (true) {
        if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
            std::cerr << "WaitForDebugEvent failed: " << GetLastError() << std::endl;
            break;
        }

        switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            std::cout << "Exception occurred in LR1_Kalashnikova.exe!" << std::endl;
            TerminateProcess(pi.hProcess, 1);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            std::cout << "LR1_Kalashnikova.exe exited." << std::endl;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return 0;

        default:
            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
            break;
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
