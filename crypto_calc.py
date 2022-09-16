import itertools


def compute_Y(P: int, G: int, kprivate: int) -> int:
    """Returns the sender's Y-value integer for El Gamal public key tuple (P,G,Y).

    # Example
        >>> compute_Y(P=262643, G=9563, kprivate=3632)
        27459

    :param P: The sender's choice of prime P integer.
    :param G: The sender's choice of prime G generator integer.
    :param kprivate: The sender's private key.
    """
    return G**kprivate % P


def elGamal_encrypt(s: str, kpub: tuple, K: list) -> list:
    """Returns the ciphertext of a message as a list of tuples (C1, C2) using the sender's choice
    of prime integer P, choice of generator integer G, and their public key Y as tuple (P, G, Y),
    and the list of random K integers for each cipherblock.

    # Example
        >>> elGamal_encrypt('PUPPIESARESMALL', (262643, 9563, 27459), [5, 3230, 9921, 176, 28119])

        [(15653, 923), (46495, 109351), (176489, 208811), (88247, 144749), (152432, 5198)]

    :param s: The string (message) to be encrypted.
    :param kpub: The public key (P=primeNumber, G=generator, Y=publicKey).
    :param K: List of random integers that is relatively prime to P-1 for each cipherblock.
    """
    P, G, Y = kpub[0], kpub[1], kpub[2]

    result = []
    plaintext = convert_to_plaintext(s).split()
    for i in range(len(plaintext)):
        C1 = G**K[i] % P
        C2 = int(plaintext[i])*(Y)**K[i] % P
        result.append((C1, C2))
    return result


def elGamal_decrypt(c: list, kprivate: int, P: int) -> str:
    """Returns the decrypted ciphertext back as plaintext.

    # Example
        >>> elGamal_decrypt([(15653, 923), (46495, 109351), (176489, 208811), (88247, 144749),
        (152432, 5198)], 3632, 262643)

        '152015 150804 180017 041812 001111'

    :param c: The list of tuples containing (C1, C2) for each ciphertext block in string.
    :param kprivate: The sender's private key.
    :param P: The sender's choice of prime P integer.
    """
    result = ''
    for cBlock in c:
        # Use Python's default pow(x,y,z) rather than math.pow().
        # pow(x,y,z) = x ** y % z ; this is more efficient.
        ans = str(pow(cBlock[0], -kprivate, P) * cBlock[1] % P)
        ans_l = len(ans)
        if ans_l < 6:
            n = 6 - ans_l
            ans = '0' * n + ans

        result += ans + ' '

    # There will be an extra space at the end of the list, so remove it.
    return result[:-1]


def rsa_encrypt(s: str, s_kpub: tuple, s_kpriv: int, r_k: tuple) -> list:
    """Returns the list of ciphertext-block encrypted from the sender's original
    message.

    ## Examples
        >>> rsa_encrypt(s='PUPPIESARESMALL', s_kpub=(
        181, 1451, 154993), s_kpriv=None, r_k=None)

        ['220160', '135824', '252355', '245799', '070707']

        >>> rsa_encrypt(s='PUPPIESARESMALL', s_kpub=(
        181, 1451, 154993), s_kpriv=95857, r_k=None)

        ['072798', '259757', '256449', '089234', '037974']

        >>> rsa_encrypt(s='PUPPIESARESMALL', s_kpub=(
        181, 1451, 154993), s_kpriv=95857, r_k=(45593, 235457))

        ['249123', '166008', '146608', '092311', '096768']

    :param s: The string (message) to be encrypted.
    :param s_kpub: The sender's public key (P=primeNumber, Q=primeNumber2, E=primeNumber3).
    :param s_priv: The sender's private key as an integer.
    :param r_k: The receiver's tuple (publicKey, privateKey) as integers.
    """
    P, Q, E = s_kpub[0], s_kpub[1], s_kpub[2]
    N = P*Q

    result = []
    plaintext = convert_to_plaintext(s).split()

    # If sender wishes to encipher message with their private key to
    # provide data and origin authenticity, kpriv cannot be None.
    # Otherwise, the public key value (E) would be used.
    if s_kpriv == None:
        s_kpriv = E

    for m in plaintext:
        ans = str(pow(int(m), s_kpriv, N))

        # Do one additional step if receiver's public key will be
        # used as part of encryption.
        if r_k != None:
            ans = str(pow(int(ans), r_k[0], N))

        ans_l = len(ans)

        # Each block must be 6 chars in length.
        # Prepend '0' if the result is too short for a block.
        if ans_l < 6:
            n = 6 - ans_l
            ans = '0' * n + ans
        result.append(ans)

    return result


def rsa_decrypt(c: list, r_kpriv: int, s_k: tuple) -> str:
    """Returns the decrypted ciphertext back as plaintext.

    # Example
        >>> rsa_decrypt(c=['249123', '166008', '146608',
                        '092311', '096768'], r_kpriv=235457, s_k=(181, 1451, 154993))

        '152015 150804 180017 041812 001111'

    :param c: The list of each ciphertext block in string.
    :param r_kpriv: The receiver's private key.
    :param s_k: The sender's public key tuple (P=primeNumber, Q=primeNumber2, E=primeNumber3).
    """
    P, Q, E = s_k[0], s_k[1], s_k[2]
    N = P*Q
    result = ''
    for cBlock in c:
        # Use Python's default pow(x,y,z) rather than math.pow().
        # pow(x,y,z) = x ** y % z ; this is more efficient.
        ans = str(pow(pow(int(cBlock), r_kpriv, N), E, N))
        ans_l = len(ans)
        if ans_l < 6:
            n = 6 - ans_l
            ans = '0' * n + ans

        result += ans + ' '

    # There will be an extra space at the end of the list, so remove it.
    return result[:-1]


def convert_to_plaintext(s: str) -> str:
    """Returns the plaintext of a string.

    # Example
        >>> convert_to_plaintext('PUPPIESARESMALL')
        '152015 150804 180017 041812 001111'

    :param s: The string (message) to converted into plain text for eventual ciphertext conversion.
    """
    result = ''
    s = s.upper()
    for i in range(len(s)):
        if i % 3 != 0 or i == 0:
            result += ASCII[s[i]]
        else:
            result += ' ' + ASCII[s[i]]
    return result


def convert_to_original(plaintext: str) -> str:
    """Returns the original string message from plaintext.

    # Example
        >>> convert_to_original('152015 150804 180017 041812 001111')
       'PUPPIESARESMALL'

    :param plaintext: 
    """

    # Parse each plaintext block as a separate list of individual chars represented by ASCII, then
    # merge into one single list.
    # Before:
    # [['15', '20', '15'], ['15', '08', '04'], ['18', '00', '17'], ['41', '81', '2'], ['11', '11']]
    # After:
    # ['15', '20', '15', '15', '08', '04', '18', '00', '17', '41', '81', '2', '11', '11']
    parsed = list(itertools.chain.from_iterable([[block[i:i+2]
                                                  for i in range(0, len(block), 2)] for block in plaintext.split()]))

    result = ''
    for char in parsed:
        result += list(ASCII.keys())[list(ASCII.values()).index(char)]
    return result


def compute_merkleScheme(C: list, K: int) -> int:
    """Returns the h(1,4) root node value. Assumes that N=4.

    ## Examples
        >>> compute_merkle(C=[3,6,21,72], K=16)
        6
        >>> compute_merkle(C=[9, 72, 199, 134], K=32)
        30
        >>> compute_merkle(C=[5,20,115,98], K=32)
        14

    :param C: A list of given integers [C1, C2, C3, C4].
    :param K: A given integer.
    """
    base = [e % K for e in C]
    middle_left = (base[0] + base[1]) % K
    middle_right = (base[2] + base[3]) % K
    top = (middle_left + middle_right) % K
    return top


ASCII = {
    'A': '00', 'B': '01', 'C': '02', 'D': '03', 'E': '04',
    'F': '05', 'G': '06', 'H': '07', 'I': '08', 'J': '09',
    'K': '10', 'L': '11', 'M': '12', 'N': '13', 'O': '14',
    'P': '15', 'Q': '16', 'R': '17', 'S': '18', 'T': '19',
    'U': '20', 'V': '21', 'W': '22', 'X': '23', 'Y': '24',
    'Z': '25', ' ': '26'
}

if __name__ == '__main__':
    s = 'PUPPIESareSmAll'
    Alice_PubKey = (262643, 9563, compute_Y(P=262643, G=9563, kprivate=3632))
    ciphertext = elGamal_encrypt(s, Alice_PubKey, [5, 3230, 9921, 176, 28119])
    back2plain = elGamal_decrypt(c=ciphertext, kprivate=3632, P=262643)

    example = """
    Original message:   {}
    Plaintext:          {} 
    Encrypted message:  {}
    Decrypted message:  {}
    """

    elGamal = example.format(s, convert_to_plaintext(s),
                             ciphertext, convert_to_original(back2plain))

    # ------------------------------------------------------------------------------

    s2 = 'PUPPIESARESMALL'
    ciphertext2 = rsa_encrypt(s=s2, s_kpub=(
        181, 1451, 154993), s_kpriv=None, r_k=None)
    back2plain2 = rsa_decrypt(c=['249123', '166008', '146608',
                              '092311', '096768'], r_kpriv=235457, s_k=(181, 1451, 154993))

    rsa = example.format(s2, convert_to_plaintext(
        s2), ciphertext2, convert_to_original(back2plain2))

    # ------------------------------------------------------------------------------

    merkleScheme = compute_merkleScheme(C=[3, 6, 21, 72], K=16)

    # ------------------------------------------------------------------------------

    print(rsa)
