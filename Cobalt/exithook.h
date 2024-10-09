#pragma once

#include <iostream>

inline void RequestExitWithStatusHook(bool Force, unsigned char Code)
{
    // std::cout << "[VEH] RequestExitWithStatus Call Forced: " << Force << " ReturnCode: " << static_cast<int>(Code) << '\n';
}

inline void RequestExitHook(int Code)
{
    static char buffer[256];  
    snprintf(buffer, sizeof(buffer), "REQUEST EXIT CODE: %d\n", Code); 
    std::cout << buffer;
}

inline void UnsafeEnvironmentPopupHook(wchar_t** unknown1, unsigned __int8 _case, __int64 unknown2, char unknown3)
{
    // std::cout << "[VEH] <UnsafeEnvironmentPopup Call with Case: " << static_cast<int>(_case) << '\n';
}
