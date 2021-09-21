import sys
# Example:
#   bobby.cooke$ python3 string2Array.py tenantId "1d5551a0-f4f2-4101-9c3b-394247ec7e08"
#   CHAR tenantId[] = {'1','d','5','5','5','1','a','0','-','f','4','f','2','-','4','1','0','1','-','9','c','3','b','-','3','9','4','2','4','7','e','c','7','e','0','8',0};

name = sys.argv[1]
input = sys.argv[2]
charArray = 'CHAR {}[] = {}'.format(name,'{')
for char in input:
    tmp = "'{}',".format(char)
    charArray += tmp
charArray += '0{};'.format('}')
print(charArray)
