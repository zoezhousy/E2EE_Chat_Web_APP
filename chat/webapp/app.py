# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from markupsafe import escape

from flask_mysqldb import MySQL
from flask_session import Session

import yaml
from serverFunction.salt_hash_password import password_check_login, password_hash
from serverFunction.OTP import  generate_secret, generate_otp, generate_qrcode, verify_otp, delete_qrcode
import os
import time
from serverFunction.recoveryKey import generate_words, word_to_list, generate_seed, generate_entropy, entropy_to_mnemo, generate_numbers
from serverFunction.genCaptcha import generate_captcha, get_captcha, delete_captcha
from serverFunction.passwordBreach import check_password

# Update -Zhou - From
from flask_caching import Cache
# Update -Zhou - End

#Merge -Bai -From
import base64
from cryptography.fernet import Fernet
#https://python-guide-fil.readthedocs.io/en/latest/scenarios/crypto.html
secret_key = b'my_secret_key_here'
padded_secret_key = secret_key.ljust(32, b' ')
url_safe_key = base64.urlsafe_b64encode(padded_secret_key)
# Fernet
cipher_suite = Fernet(url_safe_key)
def encrypt_message(message_text):
    return cipher_suite.encrypt(message_text.encode())

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message).decode()
#Merge -Bai -End 

app = Flask(__name__)

# Update -Zhou -From
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
cache.init_app(app)
# Update -Zhou -End

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        path = "static/img/CAPTCHA.png"
        captcha = get_captcha(path)
        session['captcha'] = captcha
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

#Merge -Bai -From
def decrypt_messages(messages_data):
    decrypted_messages = []
    for message in messages_data:
        decrypted_message_text = decrypt_message(message['message_text'])
        message['message_text'] = decrypted_message_text
        decrypted_messages.append(message)
    return decrypted_messages
#Merge -Bai -End

@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    #Merge -Bai -From
    decrypted_messages_data = decrypt_messages(messages)
    #Merge -Bai -End

    cur.close()
    return jsonify({'messages': decrypted_messages_data})

# Update -Zhou -From
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    path = "static/img/CAPTCHA.png"
    
    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        input_captcha = userDetails['captcha']
        cur = mysql.connection.cursor()
        
        cur.execute("SELECT user_id, password FROM users WHERE username=%s",(username, ))
        account = cur.fetchone()
        failed_attempts = cache.get(f'failed_attempts:{username}')
        if failed_attempts == None:
            failed_attempts = 0
        user_id, store_password = account
        if failed_attempts < 100: # fail < 100
            if account and password_check_login(store_password, password): # login success
                if input_captcha.lower() == session.get('captcha', None).lower(): # captcha success without case-sensitive
                    cache.delete(f'failed_attempts:{username}') # delete cache
                    session['username'] = username #################
                    session['user_id'] = account[0]
                    delete_captcha(path) # delete captcha
                    flash('The password is correct, please do the OTP authentication', 'info')
                    return redirect(url_for('google_auth_login')) # direct to OTP
                else: # captcha failed
                    wait_time = min(30 * 2**(failed_attempts), 3600) # double each time failed
                    last_attempt_time = cache.get(f'last_attempt_time:{username}') # cache get last attempt time
                    if last_attempt_time and time.time() - last_attempt_time < wait_time: # time period: cannot try
                        remaining_time = wait_time - (time.time() - last_attempt_time)
                        time.sleep(wait_time)
                        error =  f"Too many failed attempts. Please wait for {remaining_time} seconds before trying again."
                    else: # can try time period
                        cache.set(f'failed_attempts:{username}', failed_attempts + 1, timeout=None)
                        cache.set(f'last_attempt_time:{username}', time.time(), timeout=None)
                        error = "Your captcha input is wrong, please try again"
            else: # fail password 
                # same with captcha failed part
                wait_time = min(30 * 2**(failed_attempts), 3600) # double each time failed
                last_attempt_time = cache.get(f'last_attempt_time:{username}')
                if last_attempt_time and time.time() - last_attempt_time < wait_time:
                    remaining_time = wait_time - (time.time() - last_attempt_time)
                    time.sleep(wait_time)
                    error =  f"Too many failed attempts. Please wait for {remaining_time} seconds before trying again."
                else:
                    cache.set(f'failed_attempts:{username}', failed_attempts + 1, timeout=None)
                    cache.set(f'last_attempt_time:{username}', time.time(), timeout=None)
                    error = "Your captcha input is wrong, please try again"
                    error = 'Invalid credentials'
        else: # fail > 100
            error = 'You have already failed for 100 attempts! You cannot log in now'
    # get captcha for refresh CAPTCHA
    captcha = get_captcha(path)
    session['captcha'] = captcha
    return render_template('login.html', error=error, captcha_path = path)
# Update -Zhou -End

# google authentication in login
@app.route('/google_auth_login', methods=['GET', 'POST'])
def google_auth_login():
    error = None
    user_id = session.get('user_id', None)

    if request.method == 'POST':
        userDetails = request.form
        OTPcode = userDetails['OTPcode'] # get OTP code entered from user

        # get OTP secret from database
        cur = mysql.connection.cursor()
        cur.execute("SELECT secret FROM otp_secrets WHERE user_id=%s", (user_id,))
        secret = cur.fetchone()

        mysql.connection.commit()

        # verify OTP
        verifier = verify_otp(OTPcode, str(secret[0]))
        if verifier == True:
            return redirect(url_for('index'))
        else:
            error = 'The OTP is not correct. Please enter the OTP again.'
    return render_template('google_auth_login.html', error = error)

# Update -Zhou -From
@app.route('/recovery_username', methods=['GET', 'POST'])
def recovery_username():
    error = None
    if request.method == 'POST':
        username = request.form['username'] # get username for get recovery wordlist
        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id FROM users WHERE username=%s",(username, ))
        user_id = cur.fetchone()

        # check if can find account or not
        if user_id[0] == None:
            error = "Cannot find your account"
        else:
            session['username'] = username
            session['user_id'] = user_id[0]
            list_number = generate_numbers()
            session['list'] = list_number
            return redirect(url_for('recovery_verify_word_login'))

    return render_template('recovery_username.html', error = error)
# Update -Zhou -End

@app.route('/recovery_verify_word_login', methods=['GET', 'POST'])
def recovery_verify_word_login():
    error = None
    list_number = session.get('list', None)
    user_id = session.get('user_id', None)
    
    if request.method == 'POST':
        word1 = request.form['word1']
        word2 = request.form['word2']
        word3 = request.form['word3']

        cur = mysql.connection.cursor()
        cur.execute("SELECT entropy FROM recovery_keys WHERE user_id=%s", (user_id,))
        entropy = cur.fetchone()

        wordlist = word_to_list(entropy_to_mnemo(str(entropy[0])))
        
        # check if generated entropy and saved entropy are same
        if word1 == wordlist[list_number[0]-1] and word2 == wordlist[list_number[1]-1] and word3 == wordlist[list_number[2]-1]:
            flash("Your words are correct! Please set passphrase.", 'info')
            session['entropy'] = entropy
            return redirect(url_for('recovery_passphrase_login'))
        else:
            error = "The word is wrong, please check your recorded words again." 
    return render_template('recovery_verify_word_login.html', number1 = list_number[0], number2 = list_number[1], number3 = list_number[2], error = error)

# Update -Zhou -From
@app.route('/recovery_passphrase_login', methods=['GET', 'POST'])
def recovery_passphrase_login():
    error = None
    user_id = session.get('user_id', None)
    username = session.get('username', None)
    if request.method == 'POST':
        entropy = session.get('entropy', None)
        passphrase = request.form['Passphrase']
        input_seed = generate_seed(entropy_to_mnemo(str(entropy[0])), passphrase)
        
        cur = mysql.connection.cursor()
        # get seed from database
        cur.execute("SELECT seed FROM recovery_keys WHERE user_id=%s", (user_id,))
        seed = cur.fetchone()
        failed_attempts = cache.get(f'failed_attempts:{username}')
        if failed_attempts == None:
            failed_attempts = 0
        if failed_attempts < 100: # fail < 100
            if input_seed == str(seed[0]): # login success
                cache.delete(f'failed_attempts:{username}') # delete cache
                flash("Your passphrase is correct.")
                return redirect(url_for('index'))
            else: # fail password 
                wait_time = min(30 * 2**(failed_attempts), 3600) # double each time failed
                last_attempt_time = cache.get(f'last_attempt_time:{username}')
                if last_attempt_time and time.time() - last_attempt_time < wait_time:
                    remaining_time = wait_time - (time.time() - last_attempt_time)
                    time.sleep(wait_time)
                    error =  f"Too many failed attempts. Please wait for {remaining_time} seconds before trying again."
                else:
                    cache.set(f'failed_attempts:{username}', failed_attempts + 1, timeout=None)
                    cache.set(f'last_attempt_time:{username}', time.time(), timeout=None)
                    error = "The passphrase is wrong, please check your passphrase again."
        else: # fail >= 100
            error = 'You have already failed for 100 attempts! You cannot log in now'
    return render_template('recovery_passphrase_login.html', error = error)
# Update -Zhou -End

# Update -Zhou -From
# registration function
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    flash("* Password need to contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character.", "info")
    if request.method == 'POST':
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']
        repassword = userDetails['Re-enter']
        
        # existing username
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        existing_user = cur.fetchone()
        count = check_password(password)
        # hash password
        hashed = password_hash(password)

        if count == None:
            count = 0
        
        if existing_user:
            error = 'Username already exists. Please choose a different username.'
        else:
            if repassword != password:
                error = 'Your second entered password is not match with the first one.'
            else:               
                if count > 1000: # Update - Zhou
                    error = "The password has been breached " + str(count) + " times. Consider choosing a different password."
                else:
                    session['username'] = username
                    session['hashpw'] = hashed

                    # QR code generation for OTP method
                    path = "static/img/"+username+".png"
                    secret = ""
                    if os.path.isfile(path) == False:
                        secret = secret + generate_secret()
                        uri = generate_otp(secret, username)
                        generate_qrcode(uri, path) # save into path
                    session['secret'] = secret

                    flash('You have successfully set up the password! Please use One-Time Password for authentication.','info')
                    return redirect(url_for('google_auth_reg'))
        
    return render_template('signup.html', error=error)
# Update -Zhou -End

# Update -Zhou -From
@app.route('/google_auth_reg', methods=['GET', 'POST'])
def google_auth_reg():
    error = None
    hashed = session.get('hashpw', None)
    username = session.get('username', None)
    
    path = "static/img/"+username+".png"

    if request.method == 'POST':
        OTPcode = request.form['OTPcode']
        secret = session.get('secret', None)
        # google authenticator
        if os.path.isfile(path) == False:
            uri = generate_otp(secret, username)
            generate_qrcode(uri, path) # save into path

        verifier = verify_otp(OTPcode, str(secret))
        failed_attempts = cache.get(f'failed_attempts:{username}')
        if failed_attempts == None:
            failed_attempts = 0
        if failed_attempts < 100: # fail < 100
            if verifier == True: ###########################################
                cache.delete(f'failed_attempts:{username}') # delete cache
                delete_qrcode(path)
                wordlist = generate_words()
                entropy = generate_entropy(wordlist)
                session['entropy'] = entropy # pass entropy of wordlist
                flash('OTP is correct, please use recovery key to authenticate.', 'info')
                return redirect(url_for('recovery_show_word_reg'))   
            else:
                delete_qrcode(path)
                wait_time = min(30 * 2**(failed_attempts), 3600) # double each time failed
                last_attempt_time = cache.get(f'last_attempt_time:{username}')
                if last_attempt_time and time.time() - last_attempt_time < wait_time:
                    remaining_time = wait_time - (time.time() - last_attempt_time)
                    time.sleep(wait_time)
                    error =  f"Too many failed attempts. Please wait for {remaining_time} seconds before trying again."
                else: 
                    cache.set(f'failed_attempts:{username}', failed_attempts + 1, timeout=None)
                    cache.set(f'last_attempt_time:{username}', time.time(), timeout=None)
                    error = 'The OTP is not correct. Please enter the OTP again.'
        else: # fail > 100
            error = 'You have already failed for 100 attempts! You cannot log in now'
    secret = generate_secret()
    uri = generate_otp(secret, username)
    generate_qrcode(uri, path) # save into path
    session['secret'] = secret
    return render_template('google_auth_reg.html', qr_path = "../"+path, error = error)
# Update -Zhou -End

@app.route('/recovery_show_word_reg', methods=['GET', 'POST'])
def recovery_show_word_reg():
    error = None

    wordlist = word_to_list(entropy_to_mnemo(session.get('entropy', None)))
    template_arguments = {
        f"word{i+1}": wordlist[i] for i in range(len(wordlist))
    }
    template_arguments["error"] = error

    if request.method == 'POST':
        list_number = generate_numbers()
        session['list'] = list_number
        return redirect(url_for('recovery_verify_word_reg'))
        # ask for copy down in html

    return render_template('recovery_show_word_reg.html', **template_arguments)

@app.route('/recovery_verify_word_reg', methods=['GET', 'POST'])
def recovery_verify_word_reg():
    error = None
    list_number = session.get('list', None)
    
    if request.method == 'POST':
        word1 = request.form['word1']
        word2 = request.form['word2']
        word3 = request.form['word3']
        
        wordlist = word_to_list(entropy_to_mnemo(session.get('entropy', None)))
        
        # check if generated entropy and saved entropy are same
        if word1 == wordlist[list_number[0]-1] and word2 == wordlist[list_number[1]-1] and word3 == wordlist[list_number[2]-1]:
            flash("Your words are correct! Please set passphrase.", 'info')
            return redirect(url_for('recovery_passphrase_reg'))
        else:
            error = "The word is wrong, please check your recorded words again." 
    return render_template('recovery_verify_word_reg.html', number1 = list_number[0], number2 = list_number[1], number3 = list_number[2], error = error)

@app.route('/recovery_passphrase_reg', methods=['GET', 'POST'])
def recovery_passphrase_reg():
    error = None
    hashed = session.get('hashpw', None)
    username = session.get('username', None)
    secret = session.get('secret', None)

    if request.method == 'POST':
        # ask for copy down
        entropy = session.get('entropy', None)
        passphrase = request.form['Passphrase']
        seed = generate_seed(entropy_to_mnemo(entropy), passphrase)

        cur = mysql.connection.cursor()
        # save new secret while register
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed,))
        cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))
        existing_user = cur.fetchone()

        cur.execute("INSERT INTO otp_secrets (secret, user_id) VALUES (%s, %s)", (secret, existing_user,))
        
        # recovery key record(existing_user, entropy, seed)
        cur.execute("INSERT INTO recovery_keys(user_id, entropy, seed) VALUES (%s, %s, %s)", (existing_user, entropy, seed,))
        mysql.connection.commit()
        
        session.clear()
        flash("You have successfully set the passphrase!", 'info')
        return redirect(url_for('login'))


    return render_template('recovery_passphrase_reg.html', error = error)

        
@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']

    #Merge -WEI -From
    #XSS
    message_text = escape(message_text)
    #Merge -WEI -End

    #Merge -Bai -From
    assoData = "CHAT_MSG_USER_"+str(sender_id)+"_to_"+str(receiver_id)
    encrypted_message = encrypt_message(message_text)
    #Merge -Bai -End

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, encrypted_message,assoData)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message,assoData):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text,assoData) VALUES (%s, %s, %s,%s)", (sender, receiver, message,assoData,))
    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    
    #Merge -WEI -From
    #SQL injection
    try:
        peer_id = int(peer_id)
    except ValueError:
        abort(400, 'Invalid Peer ID format.')
    #Merge -WEI -End
    
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        cache.clear()
    app.run(debug=True)