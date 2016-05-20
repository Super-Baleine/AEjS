#AEjS

## Description
AEjS is a implementation of the AES (Rijndael) algorithm in Javascript

## How to use ?
__Not using Worker :__

___Encrypt :___
```javascript
// Key length can be 128/192/256 bits (higher is better)
var keyLength = 256;

// Return a base64 string
var cipherText = aes.actions.encrypt("My private content", "My p@ssW0rD", keyLength);
```

___Decrypt :___
```javascript
// Key length can be 128/192/256 bits (higher is better)
var keyLength = 256;

// First argument must be base64 of ciphertext
var plaintext = aes.actions.decrypt("sEPb517AQhWSzp95PDR2GSfXhRDPBd8DwfSrp6cM7DE1kkSyjwTeCU=", "My p@ssW0rD", keyLength);
```

__Using Worker :__

___Encrypt :___

```javascript
var keyLength = 256;
var worker = new Worker("js/aeJs.worker.js");
                
worker.postMessage({
    action: "encrypt",
    file: document.querySelector("#file").files[0],
    password: "My p@ssW0rD",
    bits: keyLength
});
```

___Decrypt :___

```javascript
var keyLength = 256;
var worker = new Worker("js/aeJs.worker.js");

worker.postMessage({
  action: "decrypt",
  file: document.querySelector("#file").files[0], // Must be encrypt with AES-"keyLength" flavor
  password: "My p@ssW0rD",
  bits: keyLength
});
```

## License
Apache 2.0

## Version
incoming...

## Contribution
Feel free to contribute to the library ;)

## Tests
incoming...
