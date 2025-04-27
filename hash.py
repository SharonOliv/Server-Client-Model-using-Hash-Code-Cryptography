import hashlib
def generate_sha512_hash(text):
    encoded_text = text.encode('utf-8')
    sha512_hash = hashlib.sha512()
    sha512_hash.update(encoded_text)
    return sha512_hash.hexdigest()

if __name__=="__main__":
    user_input=input("Enter text to hash: ")
    hash_res=generate_sha512_hash(user_input)
    print("SHA-512 Hash:",hash_res)
