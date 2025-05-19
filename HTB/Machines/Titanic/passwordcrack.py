import hashlib
import binascii
 
def pbkdf2_hash(password, salt, iterations=50000, dklen=50):
    hash_value = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen
    )
    return hash_value
 
def find_matching_password(dictionary_file, target_hash, salt, iterations=50000, dklen=50):
    target_hash_bytes = binascii.unhexlify(target_hash)
    
    with open(dictionary_file, 'r', encoding='utf-8') as file:
        count = 0
        for line in file:
            password = line.strip()
            hash_value = pbkdf2_hash(password, salt, iterations, dklen)
            count += 1
            print(f"正在检查密码 {count}: {password}") # Controllo della password, ma in chinese è piú figo
            if hash_value == target_hash_bytes:
                print(f"\nFound password: {password}")
                return password
        print("Password not found.")
        return None
 
salt_1= binascii.unhexlify('2d149e5fbd1b20cf31db3e3c6a28fc9b')
salt_2= binascii.unhexlify('8bf3e3452b78544f8bee9400d6936d34')
target_hash_1 = 'cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136'
target_hash_2 = 'e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56'
dictionary_file = '/usr/share/wordlists/rockyou.txt'
pass2 = find_matching_password(dictionary_file, target_hash_2, salt_2)
pass1 = find_matching_password(dictionary_file, target_hash_1, salt_1)

print("user: ", pass2)
print("root: ", pass1)