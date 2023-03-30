from pwn import * # pip install pwntools

Sbox = (99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22)
Sbox_bits = [x & 0x1 for x in Sbox] #computes the LSBs for Sbox to make life easier

def sendinput(plaintext): #input: plaintext, output: leaked bits count
    r = remote('saturn.picoctf.net', 55797) #change port number
    #r = process('./encrypt.py')
    line = r.recvuntil(b': ')
    r.sendline(plaintext.encode())
    final = r.recvline_regex('\d+').decode()
    r.close()
    if final[-2].isdigit():
        return final[-2:]
    return final[-1]

def testbyte(bits, zero_payload): #decreases bit leakage of given position
    for i in range(0xff): #will return before it tests every byte
        prepend = ''.join([x for x in zero_payload]) #increases each byte
        payload = "{:02x}".format(i) + "00"*(16 - len(zero_payload) - 1)
        print(prepend + payload)
        result = int(sendinput(prepend + payload)) #receives the bit leakage
        print("Bits: {}".format(result))
        if result < bits:
            return payload[0:2] #return incremented byte
        elif result > bits: #LSB was already 0
            return "00"

def findSbox(position, zero_payload, size):
    payload = zero_payload.copy()
    data_byte = []
    Sboxorigin = []
    for i in range(size):
        payload[position] = "{:02x}".format(int(zero_payload[position], 16) + i)
        data_byte.append(int(payload[position], 16))
        print(''.join(payload))
        result = int(sendinput(''.join(payload)))
        Sboxorigin.append(result)
    #print("Leaked bytes: {}".format(''.join(Sboxorigin)))
    for key in range(0xff):
        testleak = [0] * size
        for pos in range(size):
            testleak[pos] = Sbox_bits[data_byte[pos] ^ key]
        if Sboxorigin == testleak:
            print("MATCH: 0x{:02x}".format(key))
            return key

bits = int(sendinput("00"*16)) #gets bit leak standard
zero_payload = [] #list of payload bytes that produce 0 bit leakage

for i in range(0x10): #for each byte
    result = testbyte(bits, zero_payload)
    zero_payload.append(result)
    if result != "00":
        bits -= 1

assert bits == 0
#zero_payload = ['00', '01', '00', '01', '00', '00', '00', '01', '00', '02', '04', '01', '03', '03', '00', '00']
print("Zero payload: {}".format(''.join(zero_payload)))
result = sendinput(''.join(zero_payload))
assert int(result) == 0


encryption_key = []
for i in range(0x10):
    size = 20 #large number prevents false positives
    print("Testing byte: {}".format(i + 1))
    result = findSbox(i, zero_payload, size)
    encryption_key.append(result)

print("Encryption key: {}".format(''.join(['{:02x}'.format(x) for x in encryption_key]))) #formats nicely
#key = 81808c36fca7288b8a57f90907ccbae6
