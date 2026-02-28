---
trigger: always_on
---

Whenever diagnosing a problem, always scan and think about the code base first to understand what might be causing the issue.  Resort to browser tests only when absolutely necessary.

After making new changes to the project files, but before conducting any browser based tests of the project, stop what you are doing and ask me to reload the test server with the latest files before you continue.  Your browser tests will fail otherwise.  

Use the .env file to find the credentials to log in to the service so you can perform your validation tests.