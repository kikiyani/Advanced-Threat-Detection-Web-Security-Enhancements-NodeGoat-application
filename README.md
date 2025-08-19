This is the part 4 of my working on the NodeGoat application, in this part we not only analysedthe logs and did threat detection using tools like FAIL2BAN and OSSEC but also added few security measures to enhance the security. This repository contains the updated server code and along with that detailed report of the work. 
The previous 3 repositories are already updated on this github.
The report contains:

1. Intrusion Detection & Monitoring
● Set up real-time monitoring using Fail2Ban or OSSEC.
● Configure alert systems for multiple failed login attempts.

2. API Security Hardening
● Apply rate limiting using express-rate-limit to prevent brute-force attacks.
● Properly configure CORS to restrict unauthorized access.
● Secure APIs using API keys or OAuth authentication.

3. Security Headers & CSP Implementation
● Implement Content Security Policy (CSP) to prevent script
injections.
● Enforce HTTPS using Strict-Transport-Security (HSTS) headers.

Along with these all the errors and problems are mentioned that i still have to deal with as i keep working on this application. 
