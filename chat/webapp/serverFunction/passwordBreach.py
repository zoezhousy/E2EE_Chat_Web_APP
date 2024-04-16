import requests
import hashlib

def check_password(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    hashes = [line.split(':') for line in response.text.splitlines()]
    for h, count in hashes:
        if h == suffix:
            return int(count)


# count = check_password("password123")
    
# if count > 0:
#     print(f"The password has been breached {count} times. Consider choosing a different password.")
# else:
#     print("The password has not been breached. It is considered safe.")
