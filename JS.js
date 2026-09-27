"use strict";

/* =========================================
   SENTINEL PASSWORD SECURITY ANALYZER
   ========================================= */


/* ---------- DOM ---------- */

const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const clearPassword = document.getElementById("clearPassword");

const scoreElement = document.getElementById("score");
const scoreRing = document.getElementById("scoreRing");
const strengthLabel = document.getElementById("strengthLabel");
const scoreDescription = document.getElementById("scoreDescription");

const charCount = document.getElementById("charCount");

const entropyElement = document.getElementById("entropy");
const entropyFill = document.getElementById("entropyFill");
const poolSizeElement = document.getElementById("poolSize");

const generatedPassword = document.getElementById("generatedPassword");


/* ---------- COMMON PASSWORDS ---------- */

const commonPasswords = new Set([
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "administrator",
    "welcome",
    "welcome123",
    "letmein",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "login",
    "abc123",
    "111111",
    "000000",
    "123123",
    "passw0rd"
]);


/* ---------- KEYBOARD PATTERNS ---------- */

const keyboardPatterns = [
    "qwerty",
    "qwertyuiop",
    "asdf",
    "asdfgh",
    "zxcv",
    "zxcvbn",
    "qaz",
    "wsx",
    "edc",
    "rfv",
    "tgb",
    "yhn"
];


/* ---------- NAVIGATION ---------- */

const navItems = document.querySelectorAll(".nav-item");
const pages = document.querySelectorAll(".page");
const pageTitle = document.getElementById("pageTitle");

const pageNames = {
    dashboard: "Security Dashboard",
    analyzer: "Password Security Analyzer",
    generator: "Secure Password Generator",
    report: "Security Assessment Report",
    guide: "Security Guide"
};

function openPage(pageName) {

    pages.forEach(page => {
        page.classList.remove("active");
    });

    navItems.forEach(item => {
        item.classList.remove("active");
    });

    const page = document.getElementById(pageName);

    if (page) {
        page.classList.add("active");
    }

    const nav = document.querySelector(
        `.nav-item[data-page="${pageName}"]`
    );

    if (nav) {
        nav.classList.add("active");
    }

    pageTitle.textContent =
        pageNames[pageName] || "Security Dashboard";

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}

navItems.forEach(item => {

    item.addEventListener("click", () => {

        openPage(item.dataset.page);

    });

});


document.querySelectorAll("[data-open]").forEach(button => {

    button.addEventListener("click", () => {

        openPage(button.dataset.open);

    });

});


/* ---------- CLOCK ---------- */

function updateClock() {

    const now = new Date();

    document.getElementById("clock").textContent =
        now.toLocaleTimeString("en-US", {
            hour12: false
        });

}

setInterval(updateClock, 1000);

updateClock();


/* ---------- PASSWORD VISIBILITY ---------- */

togglePassword.addEventListener("click", () => {

    const visible =
        passwordInput.type === "text";

    passwordInput.type =
        visible ? "password" : "text";

    togglePassword.textContent =
        visible ? "◉" : "◌";

});


/* ---------- CHARACTER HELPERS ---------- */

function countMatches(password, regex) {

    return (password.match(regex) || []).length;

}


function hasUppercase(password) {

    return /[A-Z]/.test(password);

}


function hasLowercase(password) {

    return /[a-z]/.test(password);

}


function hasNumbers(password) {

    return /[0-9]/.test(password);

}


function hasSymbols(password) {

    return /[^A-Za-z0-9]/.test(password);

}


/* ---------- UNIQUE RATIO ---------- */

function getUniqueRatio(password) {

    if (!password.length) {
        return 0;
    }

    const unique =
        new Set(password).size;

    return unique / password.length;

}


/* ---------- SEQUENCE DETECTION ---------- */

function containsSequence(password) {

    const value =
        password.toLowerCase();

    const sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "0123456789",
        "9876543210"
    ];

    for (const sequence of sequences) {

        for (let length = 3; length <= 5; length++) {

            for (
                let i = 0;
                i <= sequence.length - length;
                i++
            ) {

                const fragment =
                    sequence.substring(i, i + length);

                if (value.includes(fragment)) {
                    return true;
                }

            }

        }

    }

    return false;
}


/* ---------- REPETITION DETECTION ---------- */

function containsRepetition(password) {

    if (/^(.)\1{3,}$/.test(password)) {
        return true;
    }

    for (let size = 1; size <= 4; size++) {

        if (password.length >= size * 3) {

            const pattern =
                password.substring(0, size);

            const repeated =
                pattern.repeat(
                    Math.floor(password.length / size)
                );

            if (
                repeated ===
                password.substring(
                    0,
                    repeated.length
                )
            ) {
                return true;
            }

        }

    }

    return false;
}


/* ---------- KEYBOARD PATTERN ---------- */

function containsKeyboardPattern(password) {

    const value =
        password.toLowerCase();

    return keyboardPatterns.some(pattern => {

        return value.includes(pattern);

    });

}


/* ---------- COMMON PASSWORD ---------- */

function isCommonPassword(password) {

    return commonPasswords.has(
        password.toLowerCase()
    );

}


/* ---------- DATE/YEAR ---------- */

function containsDatePattern(password) {

    if (/(19|20)\d{2}/.test(password)) {
        return true;
    }

    if (
        /(0[1-9]|1[0-2])([0-2][0-9]|3[01])(19|20)\d{2}/.test(password)
    ) {
        return true;
    }

    return false;
}


/* ---------- CHARACTER POOL ---------- */

function calculatePool(password) {

    let pool = 0;

    if (hasLowercase(password)) {
        pool += 26;
    }

    if (hasUppercase(password)) {
        pool += 26;
    }

    if (hasNumbers(password)) {
        pool += 10;
    }

    if (hasSymbols(password)) {
        pool += 32;
    }

    return pool;
}


/* ---------- ENTROPY ---------- */

function calculateEntropy(password) {

    const pool =
        calculatePool(password);

    if (!password.length || !pool) {
        return 0;
    }

    return Math.floor(
        password.length *
        Math.log2(pool)
    );

}


/* ---------- SCORE ---------- */

function calculateScore(password) {

    if (!password) {
        return 0;
    }

    let score = 0;


    /* LENGTH */

    if (password.length >= 8) {
        score += 10;
    }

    if (password.length >= 12) {
        score += 15;
    }

    if (password.length >= 16) {
        score += 10;
    }

    if (password.length >= 20) {
        score += 5;
    }


    /* CHARACTER TYPES */

    if (hasLowercase(password)) {
        score += 10;
    }

    if (hasUppercase(password)) {
        score += 10;
    }

    if (hasNumbers(password)) {
        score += 10;
    }

    if (hasSymbols(password)) {
        score += 10;
    }


    /* DIVERSITY */

    const ratio =
        getUniqueRatio(password);

    if (ratio >= .5) {
        score += 5;
    }

    if (ratio >= .7) {
        score += 5;
    }


    /* PATTERNS */

    if (containsSequence(password)) {
        score -= 10;
    }

    if (containsRepetition(password)) {
        score -= 10;
    }

    if (containsKeyboardPattern(password)) {
        score -= 10;
    }

    if (isCommonPassword(password)) {
        score -= 30;
    }

    if (containsDatePattern(password)) {
        score -= 5;
    }


    return Math.max(
        0,
        Math.min(100, score)
    );

}


/* ---------- STRENGTH ---------- */

function getStrength(score) {

    if (score === 0) {
        return {
            label: "WAITING FOR INPUT",
            description:
                "Enter a password to begin the assessment.",
            color: "#00d4ff"
        };
    }

    if (score < 30) {

        return {
            label: "CRITICAL",
            description:
                "This password contains significant weaknesses.",
            color: "#ef4444"
        };

    }

    if (score < 50) {

        return {
            label: "WEAK",
            description:
                "Several improvements are recommended.",
            color: "#ef4444"
        };

    }

    if (score < 70) {

        return {
            label: "MODERATE",
            description:
                "Reasonable complexity, but improvements are possible.",
            color: "#f59e0b"
        };

    }

    if (score < 85) {

        return {
            label: "STRONG",
            description:
                "Good resistance to common password patterns.",
            color: "#22c55e"
        };

    }

    return {
        label: "VERY STRONG",
        description:
            "High structural complexity with limited obvious patterns.",
        color: "#00d4ff"
    };

}


/* ---------- UI STATUS ---------- */

function setRequirement(id, pass) {

    const element =
        document.getElementById(id);

    element.classList.toggle(
        "pass",
        pass
    );

}


/* ---------- ANALYSIS ---------- */

let currentAnalysis = null;

function analyzePassword() {

    const password =
        passwordInput.value;


    /* COUNT */

    charCount.textContent =
        `${password.length} characters`;


    /* REQUIREMENTS */

    setRequirement(
        "reqLength",
        password.length >= 12
    );

    setRequirement(
        "reqUpper",
        hasUppercase(password)
    );

    setRequirement(
        "reqLower",
        hasLowercase(password)
    );

    setRequirement(
        "reqNumber",
        hasNumbers(password)
    );

    setRequirement(
        "reqSymbol",
        hasSymbols(password)
    );

    setRequirement(
        "reqUnique",
        getUniqueRatio(password) >= .5
    );


    /* METRICS */

    document.getElementById(
        "metricLength"
    ).textContent =
        password.length || "—";

    document.getElementById(
        "metricUpper"
    ).textContent =
        password
            ? countMatches(password, /[A-Z]/g)
            : "—";

    document.getElementById(
        "metricLower"
    ).textContent =
        password
            ? countMatches(password, /[a-z]/g)
            : "—";

    document.getElementById(
        "metricNumber"
    ).textContent =
        password
            ? countMatches(password, /[0-9]/g)
            : "—";

    document.getElementById(
        "metricSymbol"
    ).textContent =
        password
            ? countMatches(password, /[^A-Za-z0-9]/g)
            : "—";

    document.getElementById(
        "metricUnique"
    ).textContent =
        password
            ? `${Math.round(getUniqueRatio(password) * 100)}%`
            : "—";


    /* THREATS */

    const sequence =
        containsSequence(password);

    const repetition =
        containsRepetition(password);

    const keyboard =
        containsKeyboardPattern(password);

    const common =
        isCommonPassword(password);

    const date =
        containsDatePattern(password);


    updateThreat(
        "sequenceStatus",
        password
            ? sequence
                ? "DETECTED"
                : "NONE"
            : "—",
        sequence
    );

    updateThreat(
        "repeatStatus",
        password
            ? repetition
                ? "DETECTED"
                : "NONE"
            : "—",
        repetition
    );

    updateThreat(
        "keyboardStatus",
        password
            ? keyboard
                ? "DETECTED"
                : "NONE"
            : "—",
        keyboard
    );

    updateThreat(
        "commonStatus",
        password
            ? common
                ? "MATCH"
                : "NONE"
            : "—",
        common
    );

    updateThreat(
        "dateStatus",
        password
            ? date
                ? "DETECTED"
                : "NONE"
            : "—",
        date
    );


    /* SCORE */

    const score =
        calculateScore(password);

    const strength =
        getStrength(score);

    scoreElement.textContent =
        score;

    strengthLabel.textContent =
        strength.label;

    strengthLabel.style.color =
        strength.color;

    scoreDescription.textContent =
        strength.description;


    /* RING */

    const degrees =
        score * 3.6;

    scoreRing.style.background =
        `conic-gradient(
            ${strength.color} ${degrees}deg,
            #172230 ${degrees}deg
        )`;


    /* ENTROPY */

    const entropy =
        calculateEntropy(password);

    const pool =
        calculatePool(password);

    entropyElement.textContent =
        entropy;

    poolSizeElement.textContent =
        `Pool: ${pool}`;

    const entropyPercent =
        Math.min(
            100,
            entropy / 2
        );

    entropyFill.style.width =
        `${entropyPercent}%`;


    /* RECOMMENDATIONS */

    generateRecommendations(
        password,
        score,
        sequence,
        repetition,
        keyboard,
        common,
        date
    );


    /* SAVE CURRENT ANALYSIS */

    currentAnalysis = {
        score,
        strength: strength.label,
        length: password.length,
        entropy,
        risk:
            common || sequence || repetition || keyboard
                ? "ELEVATED"
                : "LOW"
    };


    updateReport();

}


function updateThreat(id, text, detected) {

    const element =
        document.getElementById(id);

    element.textContent = text;

    if (detected) {

        element.style.color =
            "#ef4444";

    } else if (text === "NONE") {

        element.style.color =
            "#22c55e";

    } else {

        element.style.color =
            "#7d899b";

    }

}


/* ---------- RECOMMENDATIONS ---------- */

function generateRecommendations(
    password,
    score,
    sequence,
    repetition,
    keyboard,
    common,
    date
) {

    const container =
        document.getElementById(
            "recommendationsList"
        );

    container.innerHTML = "";


    if (!password) {

        addRecommendation(
            container,
            "neutral",
            "i",
            "Enter a password to generate security recommendations."
        );

        return;

    }


    if (password.length < 12) {

        addRecommendation(
            container,
            "danger",
            "!",
            "Increase password length. Longer unique passwords generally provide greater resistance to guessing."
        );

    } else {

        addRecommendation(
            container,
            "good",
            "✓",
            "Password length meets the application's recommended threshold."
        );

    }


    if (sequence) {

        addRecommendation(
            container,
            "warning",
            "!",
            "Avoid sequential character patterns such as 123, abc or similar predictable sequences."
        );

    }


    if (repetition) {

        addRecommendation(
            container,
            "warning",
            "!",
            "Avoid repeated characters or repeated blocks."
        );

    }


    if (keyboard) {

        addRecommendation(
            container,
            "warning",
            "!",
            "Avoid predictable keyboard patterns such as QWERTY or ASDF."
        );

    }


    if (common) {

        addRecommendation(
            container,
            "danger",
            "!",
            "This password matches a common-password pattern. Choose a unique credential."
        );

    }


    if (date) {

        addRecommendation(
            container,
            "warning",
            "!",
            "Avoid obvious years or dates because they can be predictable."
        );

    }


    if (
        !sequence &&
        !repetition &&
        !keyboard &&
        !common &&
        !date
    ) {

        addRecommendation(
            container,
            "good",
            "✓",
            "No obvious predictable patterns were detected by the local analysis engine."
        );

    }


    addRecommendation(
        container,
        "neutral",
        "i",
        "Do not reuse passwords across different services. Consider using a password manager."
    );

}


function addRecommendation(
    container,
    type,
    icon,
    message
) {

    const div =
        document.createElement("div");

    div.className =
        `recommendation ${type}`;

    div.innerHTML = `
        <span>${icon}</span>
        ${message}
    `;

    container.appendChild(div);

}


/* ---------- PASSWORD INPUT ---------- */

passwordInput.addEventListener(
    "input",
    analyzePassword
);


clearPassword.addEventListener(
    "click",
    () => {

        passwordInput.value = "";

        analyzePassword();

        passwordInput.focus();

    }
);


/* ---------- GENERATOR ---------- */

const passwordLength =
    document.getElementById(
        "passwordLength"
    );

const lengthValue =
    document.getElementById(
        "lengthValue"
    );


passwordLength.addEventListener(
    "input",
    () => {

        lengthValue.textContent =
            passwordLength.value;

    }
);


function secureRandom(max) {

    if (
        window.crypto &&
        crypto.getRandomValues
    ) {

        const array =
            new Uint32Array(1);

        crypto.getRandomValues(array);

        return array[0] % max;

    }

    return Math.floor(
        Math.random() * max
    );

}


function generateSecurePassword() {

    const length =
        Number(passwordLength.value);

    let pool = "";

    const selectedPools = [];

    if (
        document.getElementById("genUpper")
            .checked
    ) {

        const chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        pool += chars;

        selectedPools.push(chars);

    }

    if (
        document.getElementById("genLower")
            .checked
    ) {

        const chars =
            "abcdefghijklmnopqrstuvwxyz";

        pool += chars;

        selectedPools.push(chars);

    }

    if (
        document.getElementById("genNumbers")
            .checked
    ) {

        const chars =
            "0123456789";

        pool += chars;

        selectedPools.push(chars);

    }

    if (
        document.getElementById("genSymbols")
            .checked
    ) {

        const chars =
            "!@#$%^&*()-_=+[]{};:,.?/";

        pool += chars;

        selectedPools.push(chars);

    }


    if (!pool) {

        generatedPassword.textContent =
            "Select at least one character type.";

        return;

    }


    let result = "";


    /* Guarantee selected character categories */

    selectedPools.forEach(chars => {

        result +=
            chars.charAt(
                secureRandom(chars.length)
            );

    });


    while (result.length < length) {

        result +=
            pool.charAt(
                secureRandom(pool.length)
            );

    }


    /* Fisher-Yates shuffle */

    const array =
        result.split("");

    for (
        let i = array.length - 1;
        i > 0;
        i--
    ) {

        const j =
            secureRandom(i + 1);

        [
            array[i],
            array[j]
        ] =
        [
            array[j],
            array[i]
        ];

    }


    generatedPassword.textContent =
        array.join("");

}


document
    .getElementById("generatePassword")
    .addEventListener(
        "click",
        generateSecurePassword
    );


/* ---------- COPY ---------- */

document
    .getElementById("copyGenerated")
    .addEventListener(
        "click",
        async () => {

            const value =
                generatedPassword.textContent;

            if (
                !value ||
                value === "Click generate"
            ) {
                return;
            }

            try {

                await navigator.clipboard.writeText(
                    value
                );

                const button =
                    document.getElementById(
                        "copyGenerated"
                    );

                button.textContent =
                    "COPIED ✓";

                setTimeout(() => {

                    button.textContent =
                        "COPY TO CLIPBOARD";

                }, 1500);

            } catch {

                alert(
                    "Clipboard access was unavailable."
                );

            }

        }
    );


/* ---------- REPORT ---------- */

function updateReport() {

    const date =
        new Date();

    document.getElementById(
        "reportDate"
    ).textContent =
        date.toLocaleString();


    if (!currentAnalysis) {

        return;

    }


    document.getElementById(
        "reportScore"
    ).textContent =
        `${currentAnalysis.score} / 100`;

    document.getElementById(
        "reportStrength"
    ).textContent =
        currentAnalysis.strength;

    document.getElementById(
        "reportLength"
    ).textContent =
        `${currentAnalysis.length} characters`;

    document.getElementById(
        "reportEntropy"
    ).textContent =
        `${currentAnalysis.entropy} bits`;

    document.getElementById(
        "reportRisk"
    ).textContent =
        currentAnalysis.risk;

}


document
    .getElementById("printReport")
    .addEventListener(
        "click",
        () => {

            window.print();

        }
    );


/* ---------- INITIAL STATE ---------- */

analyzePassword();