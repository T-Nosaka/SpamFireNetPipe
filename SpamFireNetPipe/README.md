# Name

SpamFireNetPipe


# DEMO


# Features


# Requirement

C# dotnet core 3.1
HtmlAgilityPack
MimeKit
Newtonsoft.Json

# Installation

git clone https://github.com/T-Nosaka/SpamFireNetPipe.git


# Usage

Start deamon

cd SpamFireNetPipe/SpamFireNetPipe
nohup dotnet run --configuration Release &

Stop daemon
ps -x | grep SpamFireNetPipe
kill [pid]

.Procmail
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


# Author

T.Nosaka

dangerouswoo Software

# License

"SpamFireNetPipe" is under [MIT license](https://en.wikipedia.org/wiki/MIT_License).

