#!/usr/bin/env python3

import math
import argparse

from dank.DankEncoder import DankEncoder


def main():
  parser = argparse.ArgumentParser(description='encode shellcode into custom formats')
  parser.add_argument('shellcode')
  parser.add_argument('-r', '--regex', required=False, default='([a-f]|[0-9]){8}-(([a-f]|[0-9]){4}-){3}([a-f]|[0-9]){12}')
  parser.add_argument('-l', '--length', required=False, type=int, default=36)
  args = vars(parser.parse_args())

  with open(args['shellcode'], 'rb') as handle:
    shellcode = handle.read()

  enc = DankEncoder(args['regex'], args['length'])
  capacity = math.floor(math.log2(enc.num_words(args['length'], args['length'])) / 8)
  num_chunks = math.ceil(len(shellcode) / capacity)

  print()
  print('#define SHELLCODE_SIZE %d' % len(shellcode))
  print('#define CAPACITY_SIZE %d' % capacity)
  print('#define NUM_CHUNKS %d' % num_chunks)
  print('#define FIXED_SLICE %d' % args['length'])
  print()
  print('const char* regex = "%s";' % DankEncoder.preprocess(args['regex']))
  print()
  print('char* mydata[] = {')
  for i in range(0, len(shellcode), capacity):
    chunk = shellcode[i:i+capacity]
    instance = enc.unrank(int.from_bytes(chunk, byteorder='little')).decode('utf-8')
    print('\t"%s",' % instance)
  print('};')


if __name__ == '__main__':
  main()
