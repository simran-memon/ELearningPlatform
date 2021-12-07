**CMPE#272 - Enterprise Software Platforms**

Project: **E-Learning Platform**

Team: **Akatsuki**

Team Members: **Archana Miyar Kamath , Simran Tanvir Memon, Mounica Kamireddy, Limeka Dabre**

Technologies used: **Python, Django Rest Framework, HTML, CSS, Javascript**

Project Introduction:

An e-learning platform that serves the needs of changing educational structure without compromising on the quality along with faster pace is possible with utilizing state-of-the-art technologies. For implementing this application, Python’s Django framework has been used and a default database of SQLite3 has been used. Frontend technologies such as HTML, CSS, JS and jQuery were used as a part of template engine support that Django provides. Single-sign-on authentication with SSL encryption has been provided to the users for a secure usage. SSO roles have been alloted to the users: student role , tutor role and admin role for accessing respective functional data.  Jenkins integration with Github repository for automatic builds.

**Steps for executing the project:**

1. Install Python(3.10) and Django
2. Execute the command in terminal: python -m pip install -r requirements. txt
3. Move to project directory and execute following commands: python manage.py makemigrations
                                                             python manage.py migrate
4. To run server on localhost:   python manage.py runserver
5. To check for the deployed version on AWS EC2 instance, visit: https://35.87.10.240:8443/

**Steps for local self-signed certificate creation on localhost and AWS EC2:**

1. C:\windows\system32>@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

2. C:\windows\system32>choco -

3. C:\windows\system32>choco install mkcert

4. C:\windows\system32>mkcert -install

5. For localhost: C:\Users\simra\PycharmProjects\temp\ELearningPlatform>mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1

   For AWS EC2:   C:\Users\simra\PycharmProjects\temp\ELearningPlatform>mkcert -cert-file cert.pem -key-file key.pem 35.87.10.240:8443



