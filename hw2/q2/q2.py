alp = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
dec = list("IJKDGLMNEOPXRCSTUHAVBFWZYQ")

text_file = open('question2.txt', 'r')

data = text_file.read()
decrypted = ""

for c in data:
    if c == '?':
        decrypted += ' '
    elif c == '\r':
        decrypted += '\r'
    elif c == '\n':
        decrypted += '\n'
    else:
        decrypted += dec[alp.index(c)]

with open('q2ans.txt', 'w') as f:
    f.write(decrypted)

