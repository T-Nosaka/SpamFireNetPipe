using System;
using System.IO;
using System.Net;
using System.Text;

using SpamAttack;

/*
 * .procmailrc sample
 * 

procmailrc


SUBJECT=`formail -c -xSubject:`

:0 cw
*
{
   :0 f
   |nc 192.168.210.240 8888

   :0 f
   * (1)
   { EXITCODE=1 }

   LOGFILE=/dev/null
   HOST
}
:0 ef
|formail -i "Subject: [SpamFire] $SUBJECT" |formail -A "X-Spam-Check: SpamFire"

*/

namespace SpamFireNetPipe
{
    class Program
    {
        /// <summary>
        /// Entry
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            Console.WriteLine("Start SpamFireNetPipe");

            var spamfilter = new SpamFilter();

            var configfile = Path.Combine(Environment.CurrentDirectory, "spamfire.cfg");
            //load cache
            if (File.Exists(configfile) == true)
            {
                using (var fs = new FileStream(configfile, FileMode.Open, FileAccess.Read))
                {
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        spamfilter.ImportList(sr);
                    }
                }
            }

            //Spam Check Server
            //RBL
            spamfilter.AddDNSBL("zen.spamhaus.org");
            //Custom Link
            spamfilter.AddCustomURLLink("hoge.hoge.xyz");

            var server = new netcatserver(IPAddress.Any, 8888);

            server.OnCreatePipeTerminal += (tcplient, disconnectcall) =>
            {
                return new SpamPipeTerminal(tcplient, disconnectcall);
            };

            server.OnConnect += (pipe) =>
            {
                bool bRecv = false;

                pipe.OnReceive += (targetpipe, receivebin, length ) =>
                {
                    if( length > 0 )
                        bRecv = true;
                    else
                        if(length == 0 )
                    {
                        if( bRecv == true )
                        {
                            //Finish receive
                            (pipe as SpamPipeTerminal).ReceiveStream.Position = 0;

                            var message = MimeKit.MimeMessage.Load((pipe as SpamPipeTerminal).ReceiveStream, false);

                            if( spamfilter.Fire(message) == true )
                                pipe.Send("1");
                            else
                                pipe.Send("0");

                            pipe.Dispose();
                        }
                    }

                    (pipe as SpamPipeTerminal).ReceiveStream.Write(receivebin, 0, length);
                };

                //Cache over 3 hour
                spamfilter.CacheOver(10000000L * 60L * 60L * 3L);
            };


            AppDomain.CurrentDomain.ProcessExit += (exitobj, exitargs) =>
            {
                //save cache
                using (var fs = new FileStream(configfile, FileMode.CreateNew, FileAccess.Write))
                {
                    using (var sw = new StreamWriter(fs, Encoding.UTF8))
                    {
                        spamfilter.ExportList(sw);
                    }
                }

                Console.WriteLine("Finish SpamFireNetPipe");
            };

            server.Start();

            while (true)
            {
                System.Threading.Thread.Sleep(1000);
            }
        }

    }
}
