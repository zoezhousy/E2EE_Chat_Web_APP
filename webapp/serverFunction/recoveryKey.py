# code reference: https://github.com/trezor/python-mnemonic

# mnemonic generator
from mnemonic import Mnemonic
import base64
import codecs
import secrets


# generate 12 words
def generate_words():
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=128) # generate 12 words
    # print("Words:", words)
    return words

# word in string to word in list
def word_to_list(words):
    wordlist = words.split()
    wordlist = [word for word in wordlist]
    return wordlist

# generate seed from wordlist and passphrase
def generate_seed(words: str, memory_password: str):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(words, passphrase=memory_password)
    # seed = codecs.decode(seed, 'utf-8', errors='ignore')
    seed = base64.b64encode(seed).decode('utf-8')
    # print("Seed: ", seed)
    return seed

# generate entropy from words
def generate_entropy(words: str):
    mnemo = Mnemonic("english")
    # entropy = mnemo.to_entropy(words)
    # print(entropy)
    decoded_entropy = codecs.encode(mnemo.to_entropy(words), 'hex').decode('utf-8')
    print("Entropy: ", decoded_entropy)
    return decoded_entropy

# generate wordlist from entropy
def entropy_to_mnemo(entropy):
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.to_mnemonic(codecs.decode(entropy, 'hex'))
    print("Words From Entropy:", mnemonic_phrase)
    return mnemonic_phrase

# randomly select 3 index of 12 words
def generate_numbers():
    OTP = []
    while len(OTP) < 3:
        new_number = secrets.choice(range(1, 13))
        if new_number not in OTP:
            OTP.append(new_number)
    print("Secure OTP: ", OTP)
    return OTP

# get passphrase from seed and word list
def seed_to_passphrase(seed: str, memory_password: str) -> str:
    mnemo = Mnemonic("english")
    decoded_seed = base64.b64decode(seed.encode('utf-8'))
    mnemonic_phrase = mnemo.to_mnemonic(decoded_seed)
    passphrase = mnemo.to_seed(mnemonic_phrase, passphrase=memory_password)
    return passphrase.decode('utf-8')


# test cases
# seed = "3d9ZL6HSpfaOUd+oGydRTKaDOlWLxCn++RO1z34h7fBiN3C6oKRtLNNXdDzeIi+5MgBwPYInuxb79HCBveVAHg=="
# words = "master black tortoise walk bullet sick crunch forum level cattle later beauty"

# passphrase = "password"
# seed = generate_seed(words, passphrase)
# print("Passphrase:", passphrase)

# def hash_entropy(entropy):
#     sha256_hash = hashlib.sha256(codecs.decode(entropy, 'hex')).hexdigest()
#     # hashed_entropy = bin(int(sha256_hash, 16))[2:]  # Convert the hash to binary
#     return sha256_hash

# words = generate_words()
# wordlist = word_to_list(words)
# entropy = generate_entropy(wordlist)

# entropy_to_mnemo("b0e6e961e9ef7a3cfe63fe0a28012df8")
# generate_seed("retire love arm flower glory decline insect job easy recall myself elevator", "password")
# generate_entropy("rail dance flash stable waste bunker wet lemon any divorce enter utility")

# +E9JHFYCISqhbwjg1Q3M5iJVhDo6JNpE/C44WYfYdhVEJbXfYvW+xP1dptIAJLPwlT8dC/KeHFyLSQxZiEcD4Q==
# +E9JHFYCISqhbwjg1Q3M5iJVhDo6JNpE/C44WYfYdhVEJbXfYvW+xP1dptIAJLPwlT8dC/KeHFyLSQxZiEcD4Q==
# mnemo = Mnemonic("english")
# words = generate_words()
# word_to_list(words)
# generate_seed(words, "password")
# generate_entropy(words)

# generate_seed("math people antique finger perfect arrow infant flavor poet gift dash obvious", "password")
# generate_entropy( "math people antique finger perfect arrow infant flavor poet gift dash obvious")
# entropy_to_mnemo("89145827ab7a30195cd2c5a72c38decc")
# seed: /GgqStnn+aDGF/GuGd8x7IP0iOzFoLzMlcsFDz1G5f0BEM2cVHB3OhCyBAhcFTAqylnph3S7uNGzN5fAGAZVBg==
# entropy: 89145827ab7a30195cd2c5a72c38decc

