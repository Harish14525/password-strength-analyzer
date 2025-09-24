
#!/usr/bin/env python3
"""
password_checker.py

A simple password strength analyzer for educational purposes.

Usage:
    python password_checker.py         # prompts for a password (hidden)
    python password_checker.py --password "MyP@ssw0rd!"   # analyze given password (careful: appears on process list)
    python password_checker.py --test  # run built-in sample tests

Author: ChatGPT (example)
"""

import argparse
import getpass
import re
import sys

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "password1",
    "111111", "1234567", "iloveyou", "admin", "welcome", "letmein",
    "monkey", "dragon", "baseball"
}

SIMPLE_WORDS = {"password", "admin", "user", "welcome", "qwerty", "letmein", "dragon", "baseball", "sunshine"}


def score_password(pw: str) -> dict:
    """
    Analyze the password and return a dict with a numeric score (0..8), checks passed,
    and suggestions.
    """
    reasons = []
    suggestions = []
    score = 0
    length = len(pw)

    # Length checks
    if length >= 8:
        score += 1
        reasons.append("length>=8")
    else:
        suggestions.append("Use at least 8 characters (preferably 12+).")

    if length >= 12:
        score += 1
        reasons.append("length>=12")
    else:
        suggestions.append("Longer passwords (12+ chars) are much stronger.")

    # Character class checks
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(not c.isalnum() for c in pw)

    if has_lower:
        score += 1
        reasons.append("has_lower")
    else:
        suggestions.append("Add lowercase letters.")

    if has_upper:
        score += 1
        reasons.append("has_upper")
    else:
        suggestions.append("Add uppercase letters.")

    if has_digit:
        score += 1
        reasons.append("has_digit")
    else:
        suggestions.append("Add digits (0-9).")

    if has_special:
        score += 1
        reasons.append("has_special")
    else:
        suggestions.append("Add special characters (e.g. @,#,$,%).")

    # Common-password check (small built-in list for demo)
    if pw.lower() not in COMMON_PASSWORDS:
        score += 1
        reasons.append("not_common_password")
    else:
        suggestions.append("Do NOT use common or leaked passwords (e.g., 'password', '123456').")

    # Uniqueness check (fraction of unique chars)
    uniq_frac = len(set(pw)) / max(1, length)
    if uniq_frac >= 0.6 and length >= 6:
        score += 1
        reasons.append("sufficient_uniqueness")
    else:
        suggestions.append("Avoid repeating the same character many times or simple patterns.")

    # Extra checks (penalties) - these do not subtract score but add suggestion
    lowered = pw.lower()
    for w in SIMPLE_WORDS:
        if w in lowered:
            suggestions.append(f"Avoid using common words like '{w}' inside the password.")

    # Detect simple sequences like 'abcd' or '1234'
    seq_found = False
    sequences = []
    for i in range(len(pw) - 2):
        chunk = pw[i:i+3].lower()
        if chunk.isalpha() and ord(chunk[1]) == ord(chunk[0]) + 1 and ord(chunk[2]) == ord(chunk[1]) + 1:
            seq_found = True
            sequences.append(chunk)
        if chunk.isdigit() and int(chunk[1]) == int(chunk[0]) + 1 and int(chunk[2]) == int(chunk[1]) + 1:
            seq_found = True
            sequences.append(chunk)
    if seq_found:
        suggestions.append("Avoid sequential characters like 'abc' or '123'.")

    # Classification
    max_score = 8
    if score <= 2:
        classification = "Very Weak"
    elif score <= 4:
        classification = "Weak"
    elif score <= 6:
        classification = "Moderate"
    elif score == 7:
        classification = "Strong"
    else:
        classification = "Very Strong"

    return {
        "password": pw,
        "length": length,
        "score": score,
        "max_score": max_score,
        "classification": classification,
        "reasons": reasons,
        "suggestions": suggestions
    }


def pretty_print(result: dict):
    pw_display = result["password"]
    print("="*60)
    print("Password Strength Analysis")
    print("-"*60)
    print(f"Password analyzed: {pw_display!r}")
    print(f"Length: {result['length']}")
    print(f"Score: {result['score']} / {result['max_score']}")
    print(f"Classification: {result['classification']}")
    if result['reasons']:
        print("\nChecks passed:")
        for r in result['reasons']:
            print(" -", r)
    if result['suggestions']:
        print("\nSuggestions to improve:")
        for s in result['suggestions']:
            print(" -", s)
    print("="*60)


def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer - password_checker.py")
    parser.add_argument("--password", "-p", help="Password to analyze (use with caution; shows in process list).")
    parser.add_argument("--test", action="store_true", help="Run sample tests and exit.")
    args = parser.parse_args()

    if args.test:
        samples = ["password123", "12345678", "S@fep4ss123", "Abcdef1!", "short", "LooooooongPassword!2023"]
        for s in samples:
            result = score_password(s)
            pretty_print(result)
        sys.exit(0)

    if args.password:
        pw = args.password
    else:
        try:
            pw = getpass.getpass("Enter password to analyze (input hidden): ")
        except Exception:
            # fallback for environments that don't support getpass hiding
            pw = input("Enter password to analyze: ")

    result = score_password(pw)
    pretty_print(result)


if __name__ == "__main__":
    main()
