# RunAs-Stealer
RunAs Utility Credential Stealer implementing 3 techniques : Hooking CreateProcessWithLogonW, Smart Keylogging, Remote Debugging    

### Usage

The stolen credentials are written to `C:\Users\<Username>\Desktop\desktop.ini` ADS `log` stream.   
To get the credentials type the cmd command:
```shell
more < "C:\Users\<Username>\Desktop\desktop.ini:log"
```
To remove the stored credentials type the powershell command:
```powershell
Remove-Item -Path "C:\Users\d1rk\Desktop\desktop.ini" -Stream "log"
```

#### Hooking Demo
https://github.com/user-attachments/assets/5462c211-bb3c-44b9-b147-7129ad6ffed6   

#### Remote Debugging Demo
https://github.com/user-attachments/assets/499a4fea-bec6-409e-935c-e61b469a02d5   

#### Smart Keylogging Demo
https://github.com/user-attachments/assets/03966645-9c0a-4c0f-81cb-773383881e3f   
