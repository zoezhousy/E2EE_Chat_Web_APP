var tempKeys = { a: null, b: null };

//https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
//https://medium.com/deno-the-complete-reference/sign-verify-jwt-hmac-sha256-4aa72b27042a
async function signIV(iv, macKey) {
    const ivEncoding = new TextEncoder().encode(iv);
    //req 3.4 -Protect the IV with HMAC-SHA256 using the derived MAC key
    ivSignature = await window.crypto.subtle.sign({
        name: "HMAC",
        hash: { name: "SHA-256" },
    },
    macKey,
    ivEncoding);
    return ivSignature;
}

//https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
//Messages will be encrypted using AES in GCM mode
async function encrypt(key, plainText, macKey) {
    console.log("Let's encrypt!");
    // Associated data to unit8
    const plainTextUint8 = new TextEncoder().encode(plainText);
  
    //random iv
    const iv = window.crypto.getRandomValues(new Uint8Array(12));//96-bit IVs
    const ivSignature = await signIV(iv, macKey);//Protect the IV with HMAC-SHA256
  
    const ciphertext = await window.crypto.subtle.encrypt({
        name: "AES-GCM",
        iv: iv,
        tagLength: 128 //Authentication tags should be 128 bits
    },key,plainTextUint8
    );

    //req 3.2 -Send the IV together with the ciphertext to the recipient
    return {
      ciphertext: ciphertext,
      iv: iv,
      ivSignature: ivSignature
    };
}

//ref - https://stackoverflow.com/questions/9267899/arraybuffer-to-base64-encoded-string
function arrayBufferToBase64( buffer ) {
    var binary = '';
    var bytes = new Uint8Array( buffer );
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return window.btoa( binary );
}

//encryption message from chat.html (1 to 2)
async function eMessage1to2(myid,peer_id,eKey1to2,macKeys1to2,plainText) {
    const encryptedMessage1to2 = await encrypt(eKey1to2, plainText,macKeys1to2);
    
    //log
    if(encryptedMessage1to2!=null){
        console.log("Message encrypted from "+myid+" to "+peer_id+" successfully:", encryptedMessage1to2);
        console.log("From plain text: "+plainText)
        console.log("To encrypted text: "+arrayBufferToBase64(encryptedMessage1to2.ciphertext))
    }
    return encryptedMessage1to2
}

async function verifyIV(iv, ivSignature, macKey) {
    try {
        const ivEncoding = new TextEncoder().encode(iv);
        const result = await window.crypto.subtle.verify({
            name: "HMAC",
            hash: { name: "SHA-256" },
        },
        macKey,
        ivSignature,
        ivEncoding);
        return result;
    } 
    catch (error) {
        console.error("Error verifying IV signature:", error);
        return false;
    }
}

async function decrypt(key, ciphertext, iv, ivSignature, macKey) {
    console.log("Let's decrypt!");
    //As a recipient, verify if the given IV is valid
    const isIVValid = await verifyIV(iv, ivSignature, macKey);
    if (!isIVValid) {
        console.error("Invalid IV signature.");
        return null;
    }
    console.log("Checked valid IV signature")
    try {
        // AES-GCM decrypt
        const plainText = await window.crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: iv,
            tagLength:128
        },
        key,
        ciphertext);
        return plainText;
    } catch (error) {
        console.error("Error decrypting message:", error);
        return null;
    }
}

//decryption message from chat.html (1 to 2)
async function dMessage1to2(myID,peer_id,eKey1to2, encryptedMessage1to2,macKeys1to2) {
    const decryptedMessage1to2 = await decrypt(eKey1to2, encryptedMessage1to2.ciphertext, encryptedMessage1to2.iv,encryptedMessage1to2.ivSignature,macKeys1to2);
    if (decryptedMessage1to2 !== null) {
        const decodedText12 = new TextDecoder().decode(decryptedMessage1to2);
        console.log("Message decrypted from "+peer_id+" to "+myID+" successfully:", encryptedMessage1to2);
        console.log("From cipher text: "+arrayBufferToBase64(encryptedMessage1to2.ciphertext))
        console.log("To plain text: "+decodedText12)
		return decodedText12;
    } 
    else {
        console.error("Failed to decrypt message for user1 to user2.");
    }
} 

//http://www.java2s.com/example/nodejs/number/convert-bytes-to-hex-string.html
//References
function bytesToHexString(bytes){
    if (!bytes){
        return null;
    }

    bytes = new Uint8Array(bytes);
    var hexBytes = [];
  
    for (var i = 0; i < bytes.length; ++i) {
        var byteString = bytes[i].toString(16);
        if (byteString.length < 2){
            byteString = "0" + byteString;
        }
        hexBytes.push(byteString);
    }
    return hexBytes.join("");
}
  
function ECDH_sharedSecret(myId,peerId) {
    ecdhFromTo = "From_"+myId+"_to_"+peerId+"_"
    
    return new Promise(function(resolve, reject) {
        crypto.subtle.deriveBits({
            name: "ECDH",
            public: tempKeys.b.publicKey
        }, 
        tempKeys.a.privateKey,
        128).then(function(result) {
            console.log("Shared Secret in ECDH :", result);
            var hexString = bytesToHexString(result);
            //Local storage will store the inforamtion in the format of:
            //ecdhSS_From_myID_to_peerID_ and the hexString as it's value
            localStorage.setItem("ecdhSS_"+ecdhFromTo, hexString);
            resolve(result);
        }).catch(function(error) {
            console.error("Error deriving shared secret:", error);
            reject(error);
        });
    });
}

function ECDH_generate(id,myId,peerId) {
    ecdhFromTo = "From_"+myId+"_to_"+peerId
    return new Promise(function(resolve, reject) {
        //https://github.com/mdn/dom-examples/blob/main/web-crypto/derive-key/ecdh.js
        crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, true, ["deriveBits","deriveKey"])
        .then(function(keyPair) {
            if(id=='a'){
                tempKeys.a=keyPair;
            }
            else{
                tempKeys.b=keyPair;
            }
            // In the form of <<-ECDH_Public_Key_From_myid_to_peerid
            localStorage.setItem("ECDH_Public_Key_"+ecdhFromTo,keyPair.publicKey)
            localStorage.setItem("ECDH_Private_Key_"+ecdhFromTo,keyPair.privateKey)

            console.log("ECDH_Public_Key_"+ecdhFromTo+"stored in local storage successfully",
            localStorage.getItem("ECDH_Public_Key_"+ecdhFromTo))

            console.log("ECDH_Private_Key_"+ecdhFromTo+"stored in local storage successfully",
            localStorage.getItem("ECDH_Private_Key_"+ecdhFromTo))

            resolve();
        })
        .catch(function(error) {
            console.error("Error generating ECDH key pair:", error);
            reject(error);
        });
    });
}

//ECDH()
//Req 1
async function establishECDH(myId,peerId) {
    console.log("ECDH connection start!");
    ///https://developer.mozilla.org/zh-CN/docs/Web/API/SubtleCrypto/deriveKey
    //Genarate key

    //From myId to peerId
    await ECDH_generate('a',myId,peerId)
    //From peerId to myId
    await ECDH_generate('b',peerId,myId)

    //establish shared secret
    const sharedSecreta = await ECDH_sharedSecret(myId,peerId);
    const sharedSecretb = await ECDH_sharedSecret(peerId,myId);

    if (sharedSecreta || sharedSecretb) {
      console.log("ECDH connection done!", sharedSecreta);
      return sharedSecreta;
    } 
    else {
      console.log("Error ECDH");
      return null;
    }
}

async function getEncryptionKey(sharedSecret,passinfo) {
    //references: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
    //The info parameter should represent the current context (e.g., “CHAT_KEY_USER1to2” for the key for user1user2, 
    //and “CHAT_MAC_USER1to2” for the MAC key for user1 user2)
    const infoEncryption = new TextEncoder().encode(passinfo);

    // The salt should be unique so another key derivation in the future produces different keys, use for instance a counter starting at 1
    const salt = window.crypto.getRandomValues(new Uint8Array(16));

    // Import key from shared secret
    const cryptoKey = await window.crypto.subtle.importKey(
        'raw', 
        sharedSecret, 
        { 
            name: "HKDF",
            hash: "SHA-256",
            length: 256
        },
        false, 
        ['deriveKey'] 
    );
  
    const key = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            salt: salt,
            info: infoEncryption,
            hash: "SHA-256",
        },
        cryptoKey,
        { name: "AES-GCM", length: 128 },
        false, 
        ["encrypt", "decrypt"]
    );
    return key;
}

async function getMACKey(sharedSecret,passmacinfo) {
    const infoMAC = new TextEncoder().encode(passmacinfo);
    const salt = window.crypto.getRandomValues(new Uint8Array(16));

    const cryptoKey = await window.crypto.subtle.importKey(
        'raw', 
        sharedSecret, 
        { 
            name: "HKDF",
            hash: "SHA-256",
            length: 256 
        },
        false, 
        ['deriveKey']
    );
  
    //references
    //https://medium.com/deno-the-complete-reference/sign-verify-jwt-hmac-sha256-4aa72b27042a
    const macKey = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            salt: salt,
            info: infoMAC,
            hash: "SHA-256",
        },
        cryptoKey,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        true,//extractable
        ["sign", "verify"]//uses
    );
    return macKey;
}

//Establish new ECDH connection
async function e2ee_ECDH(myChatId,peerChatId) {
    try {
        const sharedSecret = await establishECDH(myChatId,peerChatId);//req 1 establish a shared secret

        //Req 2
        if (sharedSecret) {
            console.log("Shared secret ok:", sharedSecret);

            //Me to peer
            const eKey1to2 = await getEncryptionKey(sharedSecret,"CHAT_KEY_USER_"+myChatId+"_to_"+peerChatId);
            console.log("Encryption key from me to peer derived successfully:", eKey1to2);
            localStorage.setItem("Encryption_Key_From_"+myChatId+"_to_"+peerChatId,eKey1to2);
    
            const macKeys1to2 = await getMACKey(sharedSecret,"CHAT_MAC_USER_"+myChatId+"_to_"+peerChatId);
            console.log("MAC keys from me to peer derived successfully:", macKeys1to2);
            localStorage.setItem("MAC_Key_From_"+myChatId+"_to_"+peerChatId,macKeys1to2);

            //Peer to me
            const eKey2to1 = await getEncryptionKey(sharedSecret,"CHAT_KEY_USER_"+peerChatId+"_to_"+myChatId);
            console.log("Encryption key from peer to me derived successfully:", eKey2to1);
            localStorage.setItem("Encryption_Key_From_"+peerChatId+"_to_"+myChatId,eKey2to1);

            const macKeys2to1 = await getMACKey(sharedSecret,"CHAT_MAC_USER_"+peerChatId+"_to_"+myChatId);
            console.log("MAC keys from peer to me derived successfully:", macKeys2to1);
            localStorage.setItem("MAC_Key_From_"+peerChatId+"_to_"+myID,macKeys2to1)

            return {
                eKey1to2: eKey1to2,
                macKeys1to2: macKeys1to2,
                eKey2to1:eKey2to1,
                macKeys2to1:macKeys2to1
            };
        }
        else {
            console.error("Failed to obtain shared secret.");
        }
    }
    catch (error) {
        console.error("Error:", error);
    }
}

//Ref -https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
function base64ToArrayBuffer(base64) {
    var binaryString = atob(base64);
    var bytes = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

async function e2ee_redrive(SS,myID,peer_id){
    console.log("Start redrive from shared seret");
    //Me to peer
    const eKey1to2 = await getEncryptionKey(base64ToArrayBuffer(SS),"CHAT_KEY_USER_"+myID+"_to_"+peer_id);
    console.log("Encryption key from me to peer rederived successfully:", eKey1to2);
    localStorage.removeItem("Encryption_Key_From_"+myID+"_to_"+peer_id);
    localStorage.setItem("Encryption_Key_From_"+myID+"_to_"+peer_id,eKey1to2);

    const macKeys1to2 = await getMACKey(base64ToArrayBuffer(SS),"CHAT_KEY_USER_"+myID+"_to_"+peer_id);
    console.log("MAC keys from me to peer rederived successfully:", macKeys1to2);
    localStorage.removeItem("MAC_Key_From_"+myID+"_to_"+peer_id);
    localStorage.setItem("MAC_Key_From_"+myID+"_to_"+peer_id,macKeys1to2);

    //Peer to me
    const eKey2to1 = await getEncryptionKey(base64ToArrayBuffer(SS),"CHAT_KEY_USER_"+peer_id+"_to_"+myID);
    console.log("Encryption key from peer to me rederived successfully:", eKey1to2);
    localStorage.removeItem("Encryption_Key_From_"+peer_id+"_to_"+myID);
    localStorage.setItem("Encryption_Key_From_"+peer_id+"_to_"+myID,eKey2to1);

    const macKeys2to1 = await getMACKey(base64ToArrayBuffer(SS),"CHAT_KEY_USER_"+peer_id+"_to_"+myID);
    console.log("MAC keys from peer to me rederived successfully:", macKeys2to1);
    localStorage.removeItem("MAC_Key_From_"+peer_id+"_to_"+myID)
    localStorage.setItem("MAC_Key_From_"+peer_id+"_to_"+myID,macKeys2to1)

    return {
        eKey1to2: eKey1to2,
        macKeys1to2: macKeys1to2,
        eKey2to1:eKey2to1,
        macKeys2to1:macKeys2to1
    };
}