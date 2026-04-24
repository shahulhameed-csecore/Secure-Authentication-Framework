/*
 * ═══════════════════════════════════════════════════════════════════
 *  SecureAuth — C Performance Engine  (security_c/validation.c)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Compiled as a shared library and called from Python via ctypes.
 *  Provides high-speed, low-level security primitives:
 *
 *    1. validate_input_fast()      — O(n) charset + length scan
 *    2. detect_attack_pattern()    — SQL injection / XSS / pattern scan
 *    3. calculate_security_score() — integer 0-100 score engine
 *    4. count_char_repeats()       — detect brute-force-style patterns
 *
 *  Compile:
 *    bash security_c/build.sh
 *    OR:
 *    gcc -shared -fPIC -O2 -o security_c/libsecurity.so security_c/validation.c
 * ═══════════════════════════════════════════════════════════════════
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Constants ────────────────────────────────────────────────── */
#define MAX_INPUT_LENGTH  256
#define MAX_PASSWORD_LEN  128
#define MAX_USERNAME_LEN   32
#define ATTACK_FLAG_NONE    0
#define ATTACK_FLAG_LENGTH  1
#define ATTACK_FLAG_SQLI    2
#define ATTACK_FLAG_XSS     4
#define ATTACK_FLAG_REPEAT  8
#define ATTACK_FLAG_CTRL   16

/* ── SQL injection token table ────────────────────────────────── */
static const char *SQL_PATTERNS[] = {
    "' OR ",  "' or ",
    "\" OR ", "\" or ",
    "1=1",    "1 = 1",
    "DROP ",  "drop ",
    "SELECT ","select ",
    "INSERT ","insert ",
    "DELETE ","delete ",
    "UPDATE ","update ",
    "UNION " ,"union ",
    "--",     "/*",    "*/",
    "xp_",    "EXEC ", "exec ",
    "CAST(", "cast(",
    "CHAR(", "char(",
    NULL
};

/* ── XSS token table ──────────────────────────────────────────── */
static const char *XSS_PATTERNS[] = {
    "<script", "</script",
    "javascript:", "onerror=",
    "onload=",     "onclick=",
    "alert(",      "eval(",
    "<iframe",     "<img",
    "<svg",        "document.",
    "window.",     NULL
};

/* ═══════════════════════════════════════════════════════════════
 *  validate_input_fast
 *  Returns 1 (valid) or 0 (invalid).
 *  Checks: max_len, printable chars, no control chars.
 * ═══════════════════════════════════════════════════════════════ */
int validate_input_fast(const char *input, int max_len) {
    if (!input) return 0;

    int len = 0;
    const char *p = input;

    while (*p) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7F) {
            return 0;
        }
        len++;
        if (len > max_len) return 0;
        p++;
    }

    if (len == 0) return 0;
    return 1;
}

/* ═══════════════════════════════════════════════════════════════
 *  validate_username
 *  Strict: only [a-zA-Z0-9_], length 3–32.
 * ═══════════════════════════════════════════════════════════════ */
int validate_username(const char *username) {
    if (!username) return 0;

    int len = 0;
    const char *p = username;

    while (*p) {
        char c = *p;
        if (!isalnum((unsigned char)c) && c != '_') return 0;
        len++;
        if (len > MAX_USERNAME_LEN) return 0;
        p++;
    }

    return (len >= 3) ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════
 *  count_char_repeats
 *  Returns the maximum consecutive identical char run length.
 * ═══════════════════════════════════════════════════════════════ */
int count_char_repeats(const char *input) {
    if (!input || !*input) return 0;

    int max_run = 1, run = 1;
    const char *p = input + 1;

    while (*p) {
        if (*p == *(p - 1)) {
            run++;
            if (run > max_run) max_run = run;
        } else {
            run = 1;
        }
        p++;
    }
    return max_run;
}

/* ═══════════════════════════════════════════════════════════════
 *  detect_attack_pattern
 *  Returns a bitmask of ATTACK_FLAG_* values.
 *  0 = clean.  Non-zero = attack detected.
 * ═══════════════════════════════════════════════════════════════ */
int detect_attack_pattern(const char *input) {
    if (!input) return ATTACK_FLAG_CTRL;

    int flags = ATTACK_FLAG_NONE;
    int len   = (int)strlen(input);

    if (len > MAX_INPUT_LENGTH) {
        flags |= ATTACK_FLAG_LENGTH;
    }

    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c < 0x20 && c != '\t') {
            flags |= ATTACK_FLAG_CTRL;
            break;
        }
    }

    for (int i = 0; SQL_PATTERNS[i] != NULL; i++) {
        if (strstr(input, SQL_PATTERNS[i]) != NULL) {
            flags |= ATTACK_FLAG_SQLI;
            break;
        }
    }

    for (int i = 0; XSS_PATTERNS[i] != NULL; i++) {
        if (strstr(input, XSS_PATTERNS[i]) != NULL) {
            flags |= ATTACK_FLAG_XSS;
            break;
        }
    }

    if (count_char_repeats(input) >= 8) {
        flags |= ATTACK_FLAG_REPEAT;
    }

    return flags;
}

/* ═══════════════════════════════════════════════════════════════
 *  calculate_security_score
 *  Returns integer 0–100 security score.
 * ═══════════════════════════════════════════════════════════════ */
int calculate_security_score(int has_otp, int role_level, int failed_attempts, int input_clean) {
    int score = 0;

    if (has_otp)           score += 40;
    if (role_level >= 3)   score += 25;
    else if (role_level == 2) score += 18;
    else if (role_level == 1) score += 12;
    else                   score += 5;

    if (input_clean) score += 20;

    int penalty = failed_attempts * 5;
    score -= penalty;

    if (score < 0)   score = 0;
    if (score > 100) score = 100;

    return score;
}

/* ═══════════════════════════════════════════════════════════════
 *  get_attack_flag_description
 * ═══════════════════════════════════════════════════════════════ */
void get_attack_flag_description(int flags, char *buf, int buf_size) {
    if (!buf || buf_size < 1) return;
    buf[0] = '\0';

    if (flags == ATTACK_FLAG_NONE) {
        snprintf(buf, buf_size, "CLEAN");
        return;
    }

    if (flags & ATTACK_FLAG_LENGTH)  strncat(buf, "EXCESSIVE_LENGTH ", buf_size - strlen(buf) - 1);
    if (flags & ATTACK_FLAG_CTRL)    strncat(buf, "CONTROL_CHARS ",    buf_size - strlen(buf) - 1);
    if (flags & ATTACK_FLAG_SQLI)    strncat(buf, "SQL_INJECTION ",    buf_size - strlen(buf) - 1);
    if (flags & ATTACK_FLAG_XSS)     strncat(buf, "XSS_ATTACK ",       buf_size - strlen(buf) - 1);
    if (flags & ATTACK_FLAG_REPEAT)  strncat(buf, "REPEAT_PATTERN",    buf_size - strlen(buf) - 1);
}
