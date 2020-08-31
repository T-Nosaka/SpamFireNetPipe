# Name

SpamFireNetPipe


# Features

This is a tool to filter Spam mail using procmail.
It is a server software that analyzes the mail contents with netcat and returns the result.
By changing SpamFilter, you can judge in various ways.
Written in C#, it can be easily modified by a Windows engineer.
Since it can be executed with dotnet core, it also works on Linux.

# Requirement

* C# dotnet core 3.1
* HtmlAgilityPack
* MimeKit
* Newtonsoft.Json

# Installation

git clone https://github.com/T-Nosaka/SpamFireNetPipe.git


# Usage

* Start deamon<br>

```bash
cd SpamFireNetPipe/SpamFireNetPipe
nohup dotnet run --configuration Release &
```

* Stop daemon<br>
```bash
ps -x | grep SpamFireNetPipe
kill [pid]
```

* .Procmail<br>
```bash
SUBJECT=`formail -c -xSubject:`

:0 cw
*
{
   :0 f
   |nc [SpamFireNetPipe active IPAddress] 8888

   :0 f
   * (1)
   { EXITCODE=1 }

   LOGFILE=/dev/null
   HOST
}
:0 ef
|formail -i "Subject: [SpamFire] $SUBJECT" |formail -A "X-Spam-Check: SpamFire"
```

* Program.cs<br>

Other DNSBLs can be added by modifying the code below.
If CUSTOMURLLINK matches the URLLINK of HTML mail, it will be judged as spam.

spamfilter.AddDNSBL("zen.spamhaus.org");<br>
spamfilter.AddCustomURLLink("hoge.hoge.xyz");<br>

* SpamFilter.cs<br>
It is possible to extend HTML checking by overriding SpamFilter.

```bash
protected override bool AnalyzaHTML(string html, OnHrefAnalyzaHTMLDelegate hrefcallback = null)
{
    var bResult = base.AnalyzaHTML(html, (targethref) =>
    {
        //XXXX Web Filter
        if (ChkXXXX(targethref) == true)
            return true;

        return false;
    });

    return bResult;
}
```


# Author

T.Nosaka

dangerouswoo Software

# License

"SpamFireNetPipe" is under [MIT license](https://en.wikipedia.org/wiki/MIT_License).

