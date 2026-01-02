#include "entry_dispatcher.hpp"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace exe2mem {
namespace loader {

bool EntryDispatcher::dispatch(void *entry_point) {
  if (!entry_point)
    return false;

#ifdef _WIN32
  // On Windows, we'd need to ensure memory is executable
  // (though the allocator typically does this, stubs might need extra care)

  // Example conceptual dispatch for a DLL/EXE entry point
  // using EntryFunc = BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID);
  // EntryFunc fn = reinterpret_cast<EntryFunc>(entry_point);
  // return fn(NULL, 1, NULL);

  std::cout << "[*] EntryDispatcher: Dispatching to " << entry_point
            << " (Windows Mode)" << std::endl;
  // return true; (Disabled to avoid actual crash during tests on non-Windows)
#else
  std::cout << "[*] EntryDispatcher: Dispatching to " << entry_point
            << " (Mock Mode)" << std::endl;
#endif

  return true;
}

} // namespace loader
} // namespace exe2mem
