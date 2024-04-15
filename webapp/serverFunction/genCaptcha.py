import random
import string
from captcha.image import ImageCaptcha
import os

def generate_captcha():
    captcha = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=4))
    return captcha



# reference: https://www.geeksforgeeks.org/generate-captcha-using-python/
def get_captcha(path):
    # Create an image instance of the given size
    image = ImageCaptcha(width = 200, height = 80)

    # Image captcha text
    captcha_text = generate_captcha()

    # generate the image of the given text
    data = image.generate(captcha_text) 

    # write the image on the given file and save it
    image.write(captcha_text, path)
    # print(captcha_text)
    return captcha_text

def delete_captcha(path):
    if os.path.exists(path):
        os.remove(path)
    else:
        print('file does not exists')
