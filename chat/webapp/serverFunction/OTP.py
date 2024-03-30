# OTP - Google authentication
import pyotp
import pyqrcode
import io
import os

def delete_qrcode():
    file_path = 'code.png'
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"File '{file_path}' deleted successfully.")
    else:
        print(f"File '{file_path}' does not exist.")

def generate_secret():
    return pyotp.random_base32()

def generate_otp(secret: str, user: str):
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(user, "E2EE Web App")
    # print(otp_uri)
    return otp_uri

# create pyqrcode
# reference: https://pythonhosted.org/PyQRCode/rendering.html
def generate_qrrcode(otp_uri: str):
    url = pyqrcode.create(otp_uri)
    url.png('code.png', scale=5)
    buffer = io.BytesIO()
    url.png(buffer)
    # print(list(buffer.getvalue()))

# verify
def verify_otp(input_pin, secret):
    verifier = pyotp.totp.TOTP(secret)
    return verifier.verify(input_pin)

secret = generate_secret()
uri= generate_otp(secret, 'Alice123')
generate_qrrcode(uri)
# while True:
#     pin = input('What is the One Time PIN?\n') 
#     print(verify_otp(pin, secret))

#     if (verify_otp(pin, secret)):
#         delete_qrcode()
#         break
#     else:
#         continue