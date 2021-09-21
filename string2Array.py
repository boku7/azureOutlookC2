import sys

name = sys.argv[1]
input = sys.argv[2]
charArray = 'CHAR {}[] = {}'.format(name,'{')
for char in input:
    tmp = "'{}',".format(char)
    charArray += tmp
charArray += '0{};'.format('}')
print(charArray)