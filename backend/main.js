const express = require('express')
const mysql = require('mysql');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const moment = require('moment-timezone');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const port = 3000;

const con = mysql.createConnection({
    host: "<host>",
    user: "<user>",
    password: "<password>",
    database: "<database>"
});

con.connect(function (err) {
    if (err) {
        throw err;
    }
    console.log("DB Connected");
});

function extractTemplate(password, dynamicMatches) {
    let prevIndex = 0;
    let template = [];
    dynamicMatches.forEach((match) => {
        const matchIndex = password.indexOf(match, prevIndex);
        const charsBefore = matchIndex - prevIndex;
        if (charsBefore > 0) {
            template.push('{c:' + charsBefore + '}');
        }
        template.push(match);
        prevIndex = matchIndex + match.length;
    });

    const charsAfterLastMatch = password.length - prevIndex;
    if (charsAfterLastMatch > 0) {
        template.push('{c:' + charsAfterLastMatch + '}');
    }

    return template.join('');
}

const ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 32 bytes key for AES-256

function encryptTemplate(template, encryptionKey = ENCRYPTION_KEY) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(encryptionKey, "hex"), iv);
    const encrypted = Buffer.concat([cipher.update(template, "utf8"), cipher.final()]);
    return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decryptTemplate(encryptedTemplate, encryptionKey = ENCRYPTION_KEY) {
    const [ivHex, encryptedHex] = encryptedTemplate.split(":");
    const encryptedText = Buffer.from(encryptedHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(encryptionKey, "hex"), Buffer.from(ivHex, "hex"));
    let decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString();
}
const dynamicParametersMap = new Map([
    ['h', (tz = 'UTC') => moment().tz(tz).format('HH')], // Час
    ['i', (tz = 'UTC') => moment().tz(tz).format('mm')], // Минути
    ['d', (tz = 'UTC') => moment().tz(tz).format('DD')], // Ден
    ['m', (tz = 'UTC') => moment().tz(tz).format('MM')], // Месец
    ['y', (tz = 'UTC') => moment().tz(tz).format('YYYY')], // Година
    ['w', (tz = 'UTC') => moment().tz(tz).format('ddd').toUpperCase()], // Седмица
    ['z', () => { }]
]);

function getDynamicParametersObject(timeZone = 'UTC') {
    const dpObject = {};
    for (const [key, func] of dynamicParametersMap.entries()) {
        dpObject[key] = func(timeZone);
    }
    return dpObject;
}

app.post('/register', (req, res) => {
    const email = req.body?.email;
    const password = req.body?.password;

    if (!email || !password) {
        return res.status(400).json({ message: 'Липсва email или парола.' });
    }

    const dynamicSectionRegex = /\{[^}:]+:[^}]+\}/g;
    const dynamicMatches = password.match(dynamicSectionRegex);

    if (!dynamicMatches || dynamicMatches.length === 0) {
        return res.status(400).json({ message: 'Паролата трябва да съдържа поне една динамична секция.' });
    }

    try {
        const template = extractTemplate(password, dynamicMatches);
        const encryptedTemplate = encryptTemplate(template);
        const hashedPassword = bcrypt.hashSync(password, 10);

        const query = 'INSERT INTO users (email, template, password) VALUES (?, ?, ?)';
        con.query(query, [email, encryptedTemplate, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ message: 'Съществува потребител с такъв email.' });
                }
                return res.status(500).json({ message: 'Възникна грешка при регистрация.' });
            }
            return res.status(201).json({ message: 'Успешна регистрация!' });
        });
    } catch (err) {
        console.log(err);
        return res.status(500).json({ message: 'Възникна грешка при обработка на данните.' });
    }
});

app.post('/parameters', (req, res) => {
    const timezone = req.body?.timezone;
    const dynamicParameters = getDynamicParametersObject(timezone);

    for (let y = 1; y <= 8; y++) {
        for (let x = 1; x <= 8; x++) {
            const randomNum = Math.floor(Math.random() * 900) + 100;
            dynamicParameters['z.' + x + '.' + y] = randomNum.toString();
        }
    }
    const uid = crypto.randomUUID();

    const query = 'INSERT INTO parameters (uid, val, expiry) VALUES (?, ?, ?)';
    con.query(query, [uid, JSON.stringify(dynamicParameters), 30], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ message: 'Възникна грешка при генериране на параметри.' });
        }
        return res.status(201).json({ uid: uid, val: dynamicParameters });
    });
});

function paramNameLength(param) {
    let nameLength = param.replace('{', '').replace('}', '').split(':');
    return { 'name': nameLength[0], 'len': parseInt(nameLength[1]) };
}

app.post('/login', (req, res) => {
    const email = req.body?.email;
    const password = req.body?.password;

    if (!email || !password) {
        return res.status(400).json({ message: 'Липсва email или парола.' });
    }

    if (password.includes('{') || password.includes('}')) {
        return res.status(400).json({ message: 'Паролата съдържа непозволени символи.' });
    }

    const session = req.body?.session;
    if (!session) {
        return res.status(400).json({ message: 'Липсва сесия.' });
    }

    const query = 'SELECT * FROM users WHERE email = ?';
    con.query(query, [email], (err, resultUser) => {
        if (err) {
            return res.status(500).json({ message: 'Възникна грешка при вход.' });
        }
        if (resultUser.length === 0) {
            return res.status(404).json({ message: 'Не е намерен потребител с този имейл.' });
        }

        const user = resultUser[0];

        const query = 'SELECT * FROM parameters WHERE uid = ?';
        con.query(query, [session], (err, resultSesison) => {
            if (resultSesison.length === 0) {
                return res.status(404).json({ message: 'Зададената сесия не е намерена.' });
            }
            const session = resultSesison[0];

            const expiryTime = moment(session.created_at).add(session.expiry, 'seconds');
            if (moment().isAfter(expiryTime)) {
                return res.status(401).json({ message: 'Зададената сесия е изтекла.' });
            }

            const dynamicParameterValues = JSON.parse(session.val);
            const decryptedTemplate = decryptTemplate(user.template);
            const sectionsRegex = /\{[^}:]+:[^}]+\}/g;
            const sectionsMatches = decryptedTemplate.match(sectionsRegex);

            let comparePassword = "";
            let currentIndex = 0;
            sectionsMatches.forEach((match) => {
                const param = paramNameLength(match);
                if (param.name === 'c') {
                    comparePassword += password.substring(currentIndex, currentIndex + param.len);
                }
                else {
                    const compareValue = password.substring(currentIndex, currentIndex + param.len);
                    if (compareValue == dynamicParameterValues[param.name]) {
                        comparePassword += match;
                    }
                }
                currentIndex += param.len;
            });

            if (!bcrypt.compareSync(comparePassword, user.password)) {
                return res.status(401).json({ message: 'Невалидни данни за вход.' });
            }

            return res.status(200).json({ message: 'Успешен вход!' });
        });
    });
});

app.listen(port, () => {
    console.log(`Аpp on port ${port}`)
});

// Специфичен код за Frontend-а, за да може да се изпълни от сървъра, не е част от API-то
const path = require('path');
app.get('/', (req, res) => {
    return res.redirect("/page-login");
});
app.get('/page-login', (req, res) => {
    return res.sendFile(path.resolve('../frontend/login.html'));
});
app.get('/page-register', (req, res) => {
    return res.sendFile(path.resolve('../frontend/register.html'));
}); 



