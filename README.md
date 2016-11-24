# SEHUTNManager-Usernamechanger
SEH UTN Manager - Username changer

If you have a SEH UTN Dongle server, you have to install the SEH UTN Manager which is mandatory to use one dongle. When using a dongle, it is marked "busy" for other users by showing the text "Occupied by <username>" in red. The username is your username of your current Windows session. This is problematic if you have multiple computers with the same username (for example if you are not on a Microsoft domain) because you can not differentiate which dongle is used by who / which computer.

The application does not provide any possibility to change this username and the company, contacted, does not wish to make any changes. This project fixes this issue.

The idea is to intercept the GetUserNameEx system call to return a selected value instead of the one that Windows would return.

When the "UTNManagerHookLauncher.exe" is executed, it opens the file "username.conf" and reads the first line as the new username. Then the application loads a DLL into memory that will hook the GetUserNameEx() system call to execute a custom function instead of the official. The custom function return the selected username (from the "username.conf") to the UTN Manager.

All the "hooking" part is based on the (great) EasyHook library : https://easyhook.github.io.
