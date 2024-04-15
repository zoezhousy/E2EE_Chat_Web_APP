# OTP - Google authentication
import pyotp
import pyqrcode # need to import pypng in docker requirement.txt
import os
# import tempfile


def delete_qrcode(path):
    if os.path.exists(path):
        os.remove(path)
    else:
        print('file does not exists')
        
def generate_secret():
    return pyotp.random_base32()

def generate_otp(secret: str, user: str):
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(user, "E2EE Web App")
    # print(otp_uri)
    return otp_uri

# create pyqrcode
# reference: https://pythonhosted.org/PyQRCode/rendering.html
def generate_qrcode(otp_uri: str, path):
    url = pyqrcode.create(otp_uri)
    # path = f'static/img/qrcode.png'
    # print(path)
    url.png(path, scale=5)


# verify
def verify_otp(input_pin, secret):
    verifier = pyotp.totp.TOTP(secret)
    # print(secret,type(secret))
    # print(input_pin,type(input_pin))
    return verifier.verify(input_pin)

# secret = 'OE7WG3EDRF4WR3ISJEXQVAOLPPQA43VG'
# uri= generate_otp(secret, 'Alice123')
# path = generate_qrcode(generate_otp(secret, 'Alice123'), './code.png')
# # PCYQPSYCX53ATNIRQNLF6IPXCNUMRLMS
# while True:
#     pin = input('What is the One Time PIN?\n') 
#     print(verify_otp(pin, secret))

#     if (verify_otp(pin, secret)):
#         delete_qrcode(path)
#         break
#     else:
#         continue