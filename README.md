"Name:" Password Strength Analyzer
'Description:' A Python-based tool that analyzes password strength using common security rules (length, case, digits, special characters, uniqueness, and common-password detection). Includes a command-line interface and sample outputs.

# features:
  - Checks password length (>= 8, >= 12)
  - Detects uppercase, lowercase, digits, and special characters
  - Warns if the password is common or weak
  - Checks character uniqueness to avoid repetition
  - Flags sequential patterns (abc, 123)
  - Provides actionable suggestions to improve strength
  - CLI modes: interactive, --password flag, and --test samples

# installation:
  steps:
    - git clone https://github.com/Harish14525/password-strength-analyzer.git
    - cd password-strength-analyzer
    - python password_checker.py

# usage:
  interactive: "python password_checker.py"
  with_password: "python password_checker.py --password 'S@fep4ss123'"
  test_mode: "python password_checker.py --test"

example_output: 
```
  ============================================================
  Password Strength Analysis
  ------------------------------------------------------------
  Password analyzed: 'S@fep4ss123'
  Length: 11
  Score: 7 / 8
  Classification: Strong

  Checks passed:
   - length>=8
   - has_lower
   - has_upper
   - has_digit
   - has_special
   - not_common_password
   - sufficient_uniqueness

  Suggestions to improve:
   - Longer passwords (12+ chars) are much stronger.
  ============================================================
```
# screenshots:
  - name: Weak Password
    file: screenshot_password123.png
  - name: Strong Password
    file: screenshot_H@rish@2K5.png

# structure:
  - password_checker.py
  - README.md
  - screenshot_password123.png
  - screenshot_Satfep4ss123.png

# learning_outcome:
  - Understand password vulnerabilities
  - Apply Python string methods (any(), isupper(), isdigit(), etc.)
  - Gain practical experience in building a cybersecurity tool

# disclaimer: 
  This tool is for educational purposes only.
  Do not use it to test other people’s passwords or systems without permission.

author: Harish Babu G
date: September 2025
