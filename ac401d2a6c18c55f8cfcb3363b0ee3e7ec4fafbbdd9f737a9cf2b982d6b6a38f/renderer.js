// TODO:
// - ADD ENCRYPTION

/* Modules */

const WebSocket = require("ws");
const crypto = require('crypto');
const { ipcRenderer } = require('electron');

/* Classes */

class EllipticCurve {
    constructor(a, b, p) {
        this.a = BigInt(a);
        this.b = BigInt(b);
        this.p = BigInt(p);
    }

    modInverse(value, mod) {
        return this.modPow(value, mod - 2n, mod);
    }

    modPow(base, exp, mod) {
        let result = 1n;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2n === 1n) {
                result = (result * base) % mod;
            }
            exp = exp >> 1n;
            base = (base * base) % mod;
        }
        return result;
    }

    add(P, Q) {
        if (P[0] === null && P[1] === null) return Q;
        if (Q[0] === null && Q[1] === null) return P;

        let [x1, y1] = P;
        let [x2, y2] = Q;

        x1 = BigInt(x1);
        y1 = BigInt(y1);
        x2 = BigInt(x2);
        y2 = BigInt(y2);

        let m;
        if (x1 === x2 && y1 === y2) {
            m = (3n * x1 ** 2n + this.a) * this.modInverse(2n * y1, this.p) % this.p;
        } else {
            m = (y2 - y1) * this.modInverse(x2 - x1, this.p) % this.p;
        }

        let x3 = (m ** 2n - x1 - x2) % this.p;
        let y3 = (m * (x1 - x3) - y1) % this.p;

        return [x3, y3];
    }

    multiply(P, k) {
        let Q = [null, null];
        let R = P;

        k = BigInt(k);

        while (k > 0n) {
            if (k % 2n === 1n) {
                Q = this.add(Q, R);
            }
            R = this.add(R, R);
            k = k >> 1n;
        }

        return Q;
    }
}

class EllipticOperations {
    constructor() {
        this.G = [
            0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66n,
            0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650n
        ];
        this.n = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409n;
        this.hashValues = [];
        this.k = [];
        this.initializeConstants();
    }

    initializeConstants() {
        const maxWord = Math.pow(2, 32);
        let primeCounter = this.k.length;

        const isPrime = (num) => {
            for (let factor = 2, limit = Math.sqrt(num); factor <= limit; ++factor) {
                if (num % factor === 0) return false;
            }
            return true;
        };

        const getFractionalBits = (num) => ((num - Math.floor(num)) * maxWord) | 0;

        for (let candidate = 2; primeCounter < 64; candidate++) {
            if (isPrime(candidate)) {
                if (primeCounter < 8) {
                    this.hashValues[primeCounter] = getFractionalBits(Math.sqrt(candidate));
                }
                this.k[primeCounter++] = getFractionalBits(Math.cbrt(candidate));
            }
        }
    }

    rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    hash(ascii) {
        const lengthProperty = 'length';
        let result = '';
        const words = [];
        const asciiBitLength = ascii[lengthProperty] * 8;

        this.hashValues = this.hashValues.length ? this.hashValues : Array(8).fill(0);

        ascii += '\x80';
        while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
        
        for (let i = 0; i < ascii[lengthProperty]; i++) {
            const j = ascii.charCodeAt(i);
            if (j >> 8) return;
            words[i >> 2] = (words[i >> 2] || 0) | (j << ((3 - i) % 4) * 8);
        }
        words[words.length] = ((asciiBitLength / Math.pow(2, 32)) | 0);
        words[words.length] = (asciiBitLength);

        for (let j = 0; j < words.length;) {
            const w = words.slice(j, j += 16);
            const oldHash = this.hashValues.slice(0);

            for (let i = 16; i < 64; i++) {
                const s0 = this.rightRotate(w[i - 15], 7) ^ this.rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
                const s1 = this.rightRotate(w[i - 2], 17) ^ this.rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
            }

            for (let i = 0; i < 64; i++) {
                const s1 = this.rightRotate(this.hashValues[4], 6) ^ this.rightRotate(this.hashValues[4], 11) ^ this.rightRotate(this.hashValues[4], 25);
                const ch = (this.hashValues[4] & this.hashValues[5]) ^ (~this.hashValues[4] & this.hashValues[6]);
                const temp1 = (this.hashValues[7] + s1 + ch + this.k[i] + w[i]) | 0;
                const s0 = this.rightRotate(this.hashValues[0], 2) ^ this.rightRotate(this.hashValues[0], 13) ^ this.rightRotate(this.hashValues[0], 22);
                const maj = (this.hashValues[0] & this.hashValues[1]) ^ (this.hashValues[0] & this.hashValues[2]) ^ (this.hashValues[1] & this.hashValues[2]);
                const temp2 = (s0 + maj) | 0;

                this.hashValues = [(temp1 + temp2) | 0].concat(this.hashValues);
                this.hashValues[4] = (this.hashValues[4] + temp1) | 0;
            }

            for (let i = 0; i < 8; i++) {
                this.hashValues[i] = (this.hashValues[i] + oldHash[i]) | 0;
            }
        }

        for (let i = 0; i < 8; i++) {
            for (let j = 3; j + 1; j--) {
                const b = (this.hashValues[i] >> (j * 8)) & 255;
                result += ((b < 16) ? '0' : '') + b.toString(16);
            }
        }
        return result;
    }

    bigIntArrayToBase64(bigIntArray) {
        let bigIntStr = bigIntArray.map(b => b.toString()).join(',');
        let encoder = new TextEncoder();
        let encodedBytes = encoder.encode(bigIntStr);
        return btoa(String.fromCharCode(...encodedBytes));
    }

    base64ToBigIntArray(base64Str) {
        let decodedStr = atob(base64Str);
        let decodedBytes = new Uint8Array([...decodedStr].map(c => c.charCodeAt(0)));
        let decoder = new TextDecoder();
        let bigIntStr = decoder.decode(decodedBytes);
        return bigIntStr.split(',').map(s => BigInt(s));
    }

    bigIntToBase64(bigInt) {
        let bigIntStr = bigInt.toString();
        let encoder = new TextEncoder();
        let encodedBytes = encoder.encode(bigIntStr);
        return btoa(String.fromCharCode(...encodedBytes));
    }

    base64ToBigInt(base64Str) {
        let decodedStr = atob(base64Str);
        let decodedBytes = new Uint8Array([...decodedStr].map(c => c.charCodeAt(0)));
        let decoder = new TextDecoder();
        let bigIntStr = decoder.decode(decodedBytes);
        return BigInt(bigIntStr);
    }

    generateKeypair() {
        let privateKey = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % this.n;
        let publicKey = this.bigIntArrayToBase64(curve.multiply(this.G, privateKey));
        privateKey = this.bigIntToBase64(privateKey);
        return { privateKey, publicKey };
    }

    generateChachaKeys(privateKey, publicKey) {
        let sharedSecret = curve.multiply(this.base64ToBigIntArray(publicKey), this.base64ToBigInt(privateKey));
        const hash = this.hash(this.bigIntToBase64(sharedSecret[0]));
        const key = hash.substring(0, 32);
        const IV = hash.substring(32, 44);
        return {key, IV};
    }
}

class ChaCha20 {
    constructor(key, nonce) {
        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key);
        }
        if (!Buffer.isBuffer(nonce)) {
            nonce = Buffer.from(nonce);
        }
        
        this.state = new Uint32Array(16);
        this.key = new Uint32Array(8);
        this.nonce = new Uint32Array(3);

        this.state[0] = 0x61707865;
        this.state[1] = 0x3320646e;
        this.state[2] = 0x79622d32;
        this.state[3] = 0x6b206574;

        for (let i = 0; i < 8; i++) {
            this.key[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }

        for (let i = 0; i < 8; i++) {
            this.state[i + 4] = this.key[i];
        }

        for (let i = 0; i < 3; i++) {
            this.nonce[i] = (nonce[i * 4] << 24) | (nonce[i * 4 + 1] << 16) | (nonce[i * 4 + 2] << 8) | nonce[i * 4 + 3];
        }
        this.state[13] = 0;
        this.state[14] = this.nonce[0];
        this.state[15] = this.nonce[1];
    }

    rotl(v, c) {
        return (v << c) | (v >>> (32 - c));
    }

    quarterRound(a, b, c, d) {
        this.state[a] += this.state[b];
        this.state[d] = this.rotl((this.state[d] ^ this.state[a]), 16);
        this.state[c] += this.state[d];
        this.state[b] = this.rotl((this.state[b] ^ this.state[c]), 12);
        this.state[a] += this.state[b];
        this.state[d] = this.rotl((this.state[d] ^ this.state[a]), 8);
        this.state[c] += this.state[d];
        this.state[b] = this.rotl((this.state[b] ^ this.state[c]), 7);
    }

    chachaBlock() {
        const workingState = new Uint32Array(this.state);

        for (let i = 0; i < 10; i++) {
            this.quarterRound(0, 4, 8, 12);
            this.quarterRound(1, 5, 9, 13);
            this.quarterRound(2, 6, 10, 14);
            this.quarterRound(3, 7, 11, 15);
            this.quarterRound(0, 5, 10, 15);
            this.quarterRound(1, 6, 11, 12);
            this.quarterRound(2, 7, 8, 13);
            this.quarterRound(3, 4, 9, 14);
        }

        for (let i = 0; i < 16; i++) {
            workingState[i] += this.state[i];
        }

        return workingState;
    }

    hexToUint8Array(hex) {
        hex = hex.toUpperCase().replace(/^0x/, '');
        if (hex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }

        const uint8Array = new Uint8Array(hex.length / 2);

        for (let i = 0; i < hex.length; i += 2) {
            uint8Array[i / 2] = parseInt(hex.substr(i, 2), 16);
        }

        return uint8Array;
    }

    hexToString(hex) {
        hex = hex.toUpperCase().replace(/^0x/, '');
        if (hex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }

        let bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }

        let decoder = new TextDecoder('utf-8');
        return decoder.decode(new Uint8Array(bytes));
    }

    encrypt(plaintext) {
		plaintext = Buffer.from(plaintext);
        const ciphertext = new Uint8Array(plaintext.length);
        let keyStream = new Uint8Array(64);
        let keyStreamIndex = 64;

        for (let i = 0; i < plaintext.length; i++) {
            if (keyStreamIndex === 64) {
                keyStream = new Uint8Array(this.chachaBlock().buffer);
                keyStreamIndex = 0;
                this.state[12]++;
                if (this.state[12] === 0) {
                    this.state[13]++;
                }
            }
            ciphertext[i] = plaintext[i] ^ keyStream[keyStreamIndex++];
        }

        return Buffer.from(ciphertext).toString('hex');
    }

    decrypt(ciphertext) {
        return this.hexToString(this.encrypt(this.hexToUint8Array(ciphertext)));
    }
}

/* Variables */

var wss_host = false;
var wss_client = false;
var clients = [];
var username = "Anonymous";
var serverPassword = "";
var chacha_key = crypto.randomBytes(16).toString('hex');
var chacha_IV = crypto.randomBytes(6).toString('hex');

/* Elements */

var chatboxElement = document.getElementById('chat-content');
var textboxElement = document.getElementById('chat-input');
var messageElement = document.getElementById('b1');

/* Functions */

function getCurrentTime() {
    const now = new Date();
    let hours = now.getHours();
    const minutes = now.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12;
    hours = hours.toString().padStart(2, '0');
    return `[${hours}:${minutes} ${ampm}] `;
}

function logger(message, flag="message") {
    
    if (flag === "message")
        formattedMessage = `<p>${getCurrentTime()} ${message}</p>`;
    else if (flag === "ERR") 
        formattedMessage = `<p class='err-message'>${getCurrentTime()} ${message}</p>`;
    else if (flag === "help")
        formattedMessage = `<p class='help-message'>${message}</p>`;
    else if (flag === "help-commands")
        formattedMessage = `<p class='help-commands-message'>${message}</p>`;
    else if (flag === "newline")
        formattedMessage = `<p>&nbsp;</p>`;

    chatboxElement.innerHTML += formattedMessage;
}

function sendMessage() {
    // Send the message to all connected clients
    let message = `${username}: ${textboxElement.value}`;

    if (textboxElement.value.startsWith("/")) {
        // Treat as a command
        if (textboxElement.value.startsWith("/startServer")) {
            startServer(textboxElement.value.split(' ')[1], true);
        } else if (textboxElement.value.startsWith("/connect")) {
            if (!wss_client && textboxElement.value.split(' ')[1] != undefined) {
                serverConnect(textboxElement.value.split(' ')[1]);
            } else {
                logger("ERR: Already connected to a server or no IP address given.", "ERR");
            }
        } else if (["/clear", "/cls"].includes(textboxElement.value)) {
            chatboxElement.innerHTML = "";
        } else if (textboxElement.value.startsWith("/setName")) {
            if (!wss_client && textboxElement.value.split(' ')[1] != undefined) {
                username = textboxElement.value.split(' ')[1];
                logger(`Set username to \'${username}\'.`);
            } else {
                logger("ERR: Can't change username to nothing or while in a server.", "ERR");
            }
        } else if (textboxElement.value === "/disconnect") {
            if (wss_client) {
                wss_client.close();
                wss_client = false;
            } else {
                logger("ERR: Not connected to a server.", "ERR");
            }
        } else if (textboxElement.value === "/stopServer") {
            if (wss_host) {
                wss_host.clients.forEach((client) => {
                    client.close();
                });
                wss_host.close(() => {
                    logger('Server closed.');
                });
            } else {
                logger("ERR: Not hosting a server.", "ERR");
            }
        }  else if (["/h", "/help"].includes(textboxElement.value)) {
            logger("About:", "help");
            logger("Blackbox is a secure peer-to-peer (P2P) messaging application designed with encryption"
                + " in order to hide messages and files sent between 2 users. It utilizes Chacha20 and Elliptic Curves"
                + " which are considered secure against classical computers. This tool has an advantage in that it doesn't"
                + " use any external servers to store data, so no single entity can shut it down, and your data isn't saved.", "help");
            logger("Enjoy having actual privacy. - Aydon", "help");
            logger("", "newline");
            logger("All Commands:", "help");
            logger("/h, /help&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Displays commands.", "help-commands");
            logger("/setName &lt;username&gt;&nbsp;- Set username for servers.", "help-commands");
            logger("/setPassword &lt;pswd&gt;&nbsp;- Start server as host.", "help-commands");
            logger("/clear, /cls&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Clear chatbox.", "help-commands");
            logger("/startServer &lt;port&gt;&nbsp;- Start server as host.", "help-commands");
            logger("/stopServer&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Stop server.", "help-commands");
            logger("/connect &lt;ip:port&gt;&nbsp;&nbsp;- Connect to server.", "help-commands");
            logger("/disconnect&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Disconnect from server.", "help-commands");
            logger("", "newline");
            logger("Tips:", "help");
            logger("When running a server, port-forward so people can connect to it.", "help");
            logger("Blackbox does NOT hide IPs. To prevent this, use a trusted VPN.", "help");
            logger("When you use /disconnect when hosting a server, the server will stay on.", "help");
            logger("The default password for a server is ' '.", "help");
        } else if (textboxElement.value.startsWith("/setPassword")) {
            if (!wss_host && textboxElement.value.split(' ')[1] != undefined) {
                serverPassword = textboxElement.value.split(' ')[1];
                logger(`Set server password to \'${serverPassword}\'.`);
            } else {
                logger("ERR: Unable to set empty password or while hosting a server.", "ERR");
            }
        } else {
            logger("ERR: Invalid Command.", "ERR");
        }
    } else if (!wss_client) {
        logger("ERR: Cannot send a message without a connection.", "ERR");
    } else if (textboxElement.value === "") {
        logger("ERR: Textbox is empty.", "ERR");
    } else if (wss_client) {
        wss_client.send(message);
    }
    textboxElement.value = "";
}

function serverConnect(ip_address) {
    if (wss_client) wss_client.close();

    wss_client = new WebSocket('ws://' + ip_address);

    wss_client.onmessage = (event) => {
        if (event.data == "Password is correct. You may now chat in the server.") {
            wss_client.send(`${username} has joined the server!`);
        }
        logger(event.data);
    };

    wss_client.onclose = (event) => {
        if (event.code === 1006) {
            logger("Connection failed or timed out.");
        } else {
            logger("Connection to the server closed.");
        }
    };
}

function startServer(port) {
    // Start Server Button and Server Logic
    if (port === undefined)
        port = "8080";

    wss_host = new WebSocket.Server({ port: port });

    logger(`Server started on port ${port}.`);

    wss_host.on('connection', (ws, req) => {
        let pwflag = false;
        let ip = req.socket.remoteAddress;
        let ws_name;
        ws.send("Please enter the server password below.");

        ws.on('message', (message) => {
            if (!pwflag) {
                if (message.toString().split(' ')[1] == serverPassword) {
                    ws.send("Password is correct. You may now chat in server.");
                    pwflag = true;
                    ws_name = message.toString().split(': ')[0];
                    clients.push(ws);
                    ipcRenderer.send('main-console', `${ip.includes('::ffff:') ? ip.split('::ffff:')[1] : ip} joined as '${ws_name}'.`);
                } else {
                    ws.send("Wrong password. Try again or diconnect.");
                }
            } else {
                clients.forEach((client) => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(message);
                    }
                });
            }
        });

        ws.on('close', () => {
            ipcRenderer.send('main-console', `${ip.includes('::ffff:') ? ip.split('::ffff:')[1] : ip} / '${ws_name.toString().split(': ')[0]}' left the server.`);
            clients = clients.filter(client => client !== ws);
        });
    });
}

/* Event Listeners */

window.addEventListener("DOMContentLoaded", () => {
    logger("Welcome to Blackbox! Use /help for commands.", "help");
    logger(`Your Username is currently '${username}'.`, "help");
});

window.addEventListener("beforeunload", () => {
    if (wss_client && wss_client.readyState === WebSocket.OPEN) {
        wss_client.send(`${username} has left the server!`);
    }
});

messageElement.addEventListener('click', () => {
    // Message Button
    sendMessage();
});

textboxElement.addEventListener('keydown', function(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
});