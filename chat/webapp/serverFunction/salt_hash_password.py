import bcrypt
 
# password check by bcrypt check
# check user entered password with hashed password in database
def password_check_login(saved_password: str, input_password: str):
	if bcrypt.checkpw(input_password.encode(), saved_password.encode()):
		# print(True)
		return True
	# print(False)
	return False

# hash password by bcrypt
def password_hash(input_password: str):
    return bcrypt.hashpw(input_password.encode(), bcrypt.gensalt())
	

## following are the functions for 
# password = 'pass'
# hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
# print(hashed)
# saved = '$2b$12$sTeN6j6xS1a8d7ZKKFm9OuVtyURzSd4ik9g4dym3RJDT3zXEsBtR6'
# if bcrypt.checkpw(password.encode(), saved.encode()):
#     print("It Matches!")

print(password_check_login("$2b$12$peQ53a6o1V4AQp1i2/edPe.xeiTO5x92CIsYqYmU8elqFAHMlcBXW", "password123"))
# print(password_hash('password123'))

