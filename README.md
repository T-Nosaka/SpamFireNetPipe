# Name

SpamFireNetPipe


# DEMO


# Features


# Requirement

* C# dotnet core 3.1
* HtmlAgilityPack
* MimeKit
* Newtonsoft.Json

# Installation

git clone https://github.com/T-Nosaka/SpamFireNetPipe.git


# Usage

Start deamon<br>

```bash
cd SpamFireNetPipe/SpamFireNetPipe
nohup dotnet run --configuration Release &
```

Stop daemon<br>
```bash
ps -x | grep SpamFireNetPipe
kill [pid]
```

.Procmail<br>
```bash
SUBJECT=`formail -c -xSubject:`

:0 cw
*
{
   :0 f
   |nc <h3>[SpamFireNetPipe active IPAddress]</h3> 8888

   :0 f
   * (1)
   { EXITCODE=1 }

   LOGFILE=/dev/null
   HOST
}
:0 ef
|formail -i "Subject: [SpamFire] $SUBJECT" |formail -A "X-Spam-Check: SpamFire"
```

# Author

T.Nosaka

dangerouswoo Software

# License

"SpamFireNetPipe" is under [MIT license](https://en.wikipedia.org/wiki/MIT_License).

