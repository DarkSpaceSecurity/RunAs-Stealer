# RunAs-Stealer
RunAs Utility Credential Stealer implementing 3 techniques : Hooking CreateProcessWithLogonW, Smart Keylogging, Remote Debugging    


## Usage
The stealers are running in a while loop (the injector also in Hooking case) in the background, to kill them use Task Manager.   

The stolen credentials are written to `C:\Users\<Username>\Desktop\desktop.ini` ADS `log` stream.   

To get the credentials type the cmd command:
```shell
more < "C:\Users\<Username>\Desktop\desktop.ini:log"
```
To remove the stored credentials type the powershell command:
```powershell
Remove-Item -Path "C:\Users\d1rk\Desktop\desktop.ini" -Stream "log"
```

***N.B: Refer to the Demo down below for each use case*** 



#### Hooking Demo
https://github.com/user-attachments/assets/5462c211-bb3c-44b9-b147-7129ad6ffed6   

#### Remote Debugging Demo
https://github.com/user-attachments/assets/499a4fea-bec6-409e-935c-e61b469a02d5   

#### Smart Keylogging Demo
https://github.com/user-attachments/assets/03966645-9c0a-4c0f-81cb-773383881e3f   
