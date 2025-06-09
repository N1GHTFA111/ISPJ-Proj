# begin with the original message of length L bits
# append a single '1' bit
# append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 256) is a multiple of 2048
# append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 2048 bits
# such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 256 bit integer> , (the number of bits will be a multiple of 2048)
def padding(message):
    # convert message to binary
    print(type(message))
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    original_length = len(binary_message)
    print(f"Binary message: {binary_message}")
    print(f"Unpadded binary message length: {len(binary_message)}")

    # append 1 to the binary message
    binary_message += '1'
    print(f"New Binary message: {binary_message}")

    # append 0 bits until (original message bit length + 1 bit + K + 256 ) % 2048 = 0
    k = 0
    while (len(binary_message) + k + 256) % 2048 != 0:
        k += 1

    binary_message += '0' * k

    # append orgininal length as a 64 big endian integer to the binary message
    binary_length = format(original_length, '0256b')
    binary_message += binary_length

    return binary_message


def break_into_chunks(message):
    chunks = []
    # since i need 2048 bit chunks, thats 256 byte chunks
    for i in range(0, len(message), 256):
        chunks.append(message[i:i + 256])
    return chunks

# function below does this
# create a 100-entry message schedule array w[0..99] of 128-bit words
#     (The initial values in w[0..99] don't matter, so many implementations zero them here)
#     copy chunk into first 16 words w[0..15] of the message schedule array
#
#     Extend the first 16 words into the remaining words w[16..99] of the message schedule array:
#     for i from 16 to 99
#         s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
#         s1 := (w[i-15] rightrotate 17) xor (w[i-15] rightrotate 19) xor (w[i-15] rightshift 10)
#         w[i] := w[i-16] + s0 + w[i-7] + s1

# 128 because each message entry is a 128 bit word
def rightrotate(value, shift, bit_length=128):
    shift %= bit_length  # Ensure shift amount is within the bit length
    return (value >> shift) | (value << (bit_length - shift)) & ((1 << bit_length) - 1)

def process_chunk(chunk_message):
    # just nice for 2048 bits since its equal to 256 bytes
    words = [0] * 100
    chunk_message = chunk_message.encode('utf-8')

    # rmb in each 2048 bit chunk, there are 256 bytes

    # Convert the first 16 128-bit words from the chunk message into the words array.
    for i in range(16):
        words[i] = int.from_bytes(chunk_message[i * 16:i * 16 + 16], byteorder='big')
        # print(int.from_bytes(chunk_message[i * 4:i * 4 + 4], byteorder='big'))
    #

    for i in range(16, 100):
        s0 = (rightrotate(words[i-15], 7)) ^ (rightrotate(words[i-15], 18)) ^ (words[i-15] >> 3)
        s1 = (rightrotate(words[i-15], 17)) ^ (rightrotate(words[i-15], 19)) ^ (words[i-15] >> 10)
        words[i] = words[i-16] + s0 + words[i-7] + s1 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF # 0xFFFFFFFF is 128 bit so mask the result to only 128 bit

    return words


def hashing_sha1024(padded_message):
    # Initialize hash values:
    # (first 128 bits of the fractional parts of the square roots of the first 8 primes 2..19) x 4 sets:
    h0 = 0x6a09e6676a09e6676a09e6676a09e667
    h1 = 0xbb67ae85bb67ae85bb67ae85bb67ae85
    h2 = 0x3c6ef3723c6ef3723c6ef3723c6ef372
    h3 = 0xa54ff53aa54ff53aa54ff53aa54ff53a
    h4 = 0x510e527f510e527f510e527f510e527f
    h5 = 0x9b05688c9b05688c9b05688c9b05688c
    h6 = 0x1f83d9ab1f83d9ab1f83d9ab1f83d9ab
    h7 = 0x5be0cd195be0cd195be0cd195be0cd19

    # Initialize array of round constants:
    # (first 128 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
    k = [
        0x428a2f98d728ae22428a2f98d728ae22, 0x7137449123ef65cd7137449123ef65cd, 0xb5c0fbcfec4d3b2fb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbce9b5dba58189dbbc, 0x3956c25bf348b5383956c25bf348b538,
        0x59f111f1b605d01959f111f1b605d019, 0x923f82a4af194f9b23f82a4af194f9b, 0xab1c5ed5da6d8118ab1c5ed5da6d8118,
        0xd807aa98a3030242d807aa98a3030242, 0x12835b0145706fbe12835b0145706fbe,
        0x243185be4ee4b28c243185be4ee4b28c, 0x550c7dc3d5ffb4e2550c7dc3d5ffb4e2, 0x72be5d74f27b896f72be5d74f27b896f,
        0x80deb1fe3b1696b180deb1fe3b1696b1, 0x9bdc06a725c712359bdc06a725c71235,
        0xc19bf174cf692694c19bf174cf692694, 0xe49b69c19ef14ad2e49b69c19ef14ad2, 0xefbe4786384f25e3efbe4786384f25e3,
        0x0fc19dc68b8cd5b50fc19dc68b8cd5b5, 0x240ca1cc77ac9c65240ca1cc77ac9c65,
        0x2de92c6f592b02752de92c6f592b0275, 0x4a7484aa6ea6e4834a7484aa6ea6e483, 0x5cb0a9dcbd41fbd45cb0a9dcbd41fbd4,
        0x76f988da831153b576f988da831153b5, 0x983e5152ee66dfab983e5152ee66dfab,
        0xa831c66d2db43210a831c66d2db43210, 0xb00327c898fb213fb00327c898fb213f, 0xbf597fc7beef0ee4bf597fc7beef0ee4,
        0xc6e00bf33da88fc2c6e00bf33da88fc2, 0xd5a79147930aa725d5a79147930aa725,
        0x06ca6351e003826f06ca6351e003826f, 0x142929670a0e6e70142929670a0e6e70, 0x27b70a8546d22ffc27b70a8546d22ffc,
        0x2e1b21385c26c9262e1b21385c26c926, 0x4d2c6dfc5ac42aed4d2c6dfc5ac42aed,
        0x53380d139d95b3df53380d139d95b3df, 0x650a73548baf63de650a73548baf63de, 0x766a0abb3c77b2a8766a0abb3c77b2a8,
        0x81c2c92e47edaee681c2c92e47edaee6, 0x92722c851482353b92722c851482353b,
        0xa2bfe8a14cf10364a2bfe8a14cf10364, 0xa81a664bbc423001a81a664bbc423001, 0xc24b8b70d0f89791c24b8b70d0f89791,
        0xc76c51a30654be30c76c51a30654be30, 0xd192e819d6ef5218d192e819d6ef5218,
        0xd69906245565a910d69906245565a910, 0xf40e35855771202af40e35855771202a, 0x106aa07032bbd1b8106aa07032bbd1b8,
        0x19a4c116b8d2d0c819a4c116b8d2d0c8, 0x1e376c085141ab531e376c085141ab53,
        0x2748774cdf8eeb992747774cdf8eeb99, 0x34b0bcb5e19b48a834b0bcb5e19b48a8, 0x391c0cb3c5c95a63391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb4ed8aa4ae3418acb, 0x5b9cca4f7763e3735b9cca4f7763e373,
        0x682e6ff3d6b2b8a3682e6ff3d6b2b8a3, 0x748f82ee5defb2fc748f82ee5defb2fc, 0x78a5636f43172f6078a5636f43172f60,
        0x84c87814a1f0ab7284c87814a1f0ab72, 0x8cc702081a6439ec8cc702081a6439ec,
        0x90befffa23631e2890befffa23631e28, 0xa4506cebde82bde9a4506cebde82bde9, 0xbef9a3f7b2c67915bef9a3f7b2c67915,
        0xc67178f2e372532bc67178f2e372532b, 0xca273eceea26619cca273eceea26619c,
        0xd186b8c721c0c207d186b8c721c0c207, 0xeada7dd6cde0eb1eeada7dd6cde0eb1e, 0xf57d4f7fee6ed178f57d4f7fee6ed178,
        0x06f067aa72176fb806f067aa72176fba, 0x0a637dc5a2c898a60a637dc5a2c898a6,
        0x113f9804bef90dae113f9804bef90dae, 0x1b710b35131c471b1b710b35131c471b, 0x28db77f523047d8428db77f523047d84,
        0x32caab7b40c7249332caab7b40c72493, 0x3c9ebe0a15c9bebc3c9ebe0a15c9bebc,
        0x431d67c49c100d4c431d67c49c100d4c, 0x4cc5d4becb3e42b64cc5d4becb3e42b6, 0x597f299cfc657e2a597f299cfc657e2a,
        0x5fcb6fab3ad6faec5fcb6fab3ad6faec, 0x6c44198c4a4758176c44198c4a475817,
        0x428a2f98d728ae22428a2f98d728ae22, 0x7137449123ef65cd7137449123ef65cd, 0xb5c0fbcfec4d3b2fb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbce9b5dba58189dbbc, 0x3956c25bf348b5383956c25bf348b538,
        0x59f111f1b605d01959f111f1b605d019, 0x923f82a4af194f9b23f82a4af194f9b, 0xab1c5ed5da6d8118ab1c5ed5da6d8118,
        0xd807aa98a3030242d807aa98a3030242, 0x12835b0145706fbe12835b0145706fbe,
        0x243185be4ee4b28c243185be4ee4b28c, 0x550c7dc3d5ffb4e2550c7dc3d5ffb4e2, 0x72be5d74f27b896f72be5d74f27b896f,
        0x80deb1fe3b1696b180deb1fe3b1696b1, 0x9bdc06a725c712359bdc06a725c71235,
        0xc19bf174cf692694c19bf174cf692694, 0xe49b69c19ef14ad2e49b69c19ef14ad2, 0xefbe4786384f25e3efbe4786384f25e3,
        0x0fc19dc68b8cd5b50fc19dc68b8cd5b5, 0x240ca1cc77ac9c65240ca1cc77ac9c65,
    ]

    # next is to break data into chunks (return array of 2048 bit chunks)
    chunked_message = break_into_chunks(padded_message)
    for chunk in chunked_message:
        words = process_chunk(chunk)

        # Initialize working variables to current hash value:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        for i in range(100):
            S1 = rightrotate(e, 14) ^ rightrotate(e,27) ^ rightrotate(e,34)
            ch = (e & f) ^ ((~e) & g)
            temp1 = h + S1 + ch + k[i] + words[i]
            S0 = rightrotate(a, 7) ^ rightrotate(a, 43) ^ rightrotate(a, 67)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = S0 + maj & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

            h = g
            g = f
            f = e
            e = d + temp1 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = temp1 + temp2 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


        final_hash = (h0 << 896) | (h1 << 768) | (h2 << 640) | (h3 << 512) | (h4 << 384) | (h5 << 256) | (h6 << 128) | h7
        return hex(final_hash)[2:]