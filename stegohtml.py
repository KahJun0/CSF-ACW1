import numpy as np
import re

"Referenced from https://github.com/Simonl07/html-steganography"

prefix_regex = re.compile('^(?P<match>[\s]+)\S')
suffix_regex = re.compile('\S(?P<match>[\s]+)$')

bit_space = {
    '0': 1,
    '1': 4
}
bit_char = {
    '0': ' ',
    '1': '\t'
}
bit_flip = {
    '0': '1',
    '1': '0'
}
char_bit = {
    ' ': '0',
    '\t': '1'
}


def get_space(line, regex):
    match = regex.match(line)
    if not match:
        return ''

    trailing = match.group('match')
    return trailing


def encode_line(line, queue):
    if line.strip() == '':
        return '\n'
    trailing_spaces = get_space(line, prefix_regex)
    capacity = 0
    for s in trailing_spaces:
        capacity += bit_space[char_bit[s]]
    padded = False
    prefix = ''

    while len(queue) != 0 and bit_space[queue[0]] <= capacity:
        bit = queue.pop(0)
        capacity -= bit_space[bit]
        prefix += bit_char[bit]

    if capacity != 0:
        padded = True
        prefix += ' ' * capacity

    line = prefix + line[len(trailing_spaces):]

    if padded:
        line = re.sub('[\t \n]*$', (' ' * capacity) + "\n", line)

    return line


def to_bin(data):
    """Convert `data` to binary format as string"""
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, "08b") for i in data]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")


def encode(input_file, output_file, message):
    input_file = open(input_file, "r")
    output_file = open(output_file, "w")
    lines = input_file.readlines()
    input_file.close()
    temp = to_bin(message)

    print(f"input size(after padding): {len(temp)}")
    s = list(temp)
    results = []
    for line in lines:
        results.append(encode_line(line, s))

    if len(s) != 0:
        print(f"Insufficient space, need larger cover ({len(s)} more bits) for given message")
        output_file.writelines(results)
        output_file.close()
        return
    output_file.writelines(results)
    output_file.close()
    return f"encoded the html file: {output_file.name}"


def decode_line(line, queue):
    prefix = get_space(line, prefix_regex)
    suffix_match = re.search('\S(?P<match>[\t ]+)$', line)
    if not suffix_match:
        suffix = ''
    else:
        suffix = suffix_match.group('match')

    temp = prefix[: len(prefix) - len(suffix)]
    queue.append(temp)


def bin_2_byte(b):
    return int(b, 2).to_bytes(len(b) // 8, byteorder='big')


def decode(output_file):
    output_file = open(output_file, "r")
    lines = output_file.readlines()
    output_file.close()

    c = []
    for line in lines:
        decode_line(line, c)
    temp = ''
    c = ''.join(c)
    for x in c:
        if x == ' ':
            temp += '0'
        else:
            temp += '1'
    temp = bin_2_byte(temp)
    return f"message: {temp}"

