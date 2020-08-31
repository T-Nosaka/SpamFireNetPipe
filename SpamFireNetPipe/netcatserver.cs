using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Linq;

namespace SpamFireNetPipe
{
    /// <summary>
    /// NetCat Server
    /// </summary>
    public class netcatserver
    {
        /// <summary>
        /// Listener
        /// </summary>
        protected TcpListener m_listner;

        /// <summary>
        /// Finish flag
        /// </summary>
        protected ManualResetEvent m_terminate = new ManualResetEvent(false);

        /// <summary>
        /// Constructor
        /// </summary>
        public netcatserver(IPAddress address, int port)
        {
            m_listner = new TcpListener(address, port);
        }

        /// <summary>
        /// Connect callback type
        /// </summary>
        /// <param name="pipe"></param>
        public delegate void OnConnectDelegate(PipeTerminal pipe);

        /// <summary>
        /// Connect callback event
        /// </summary>
        public event OnConnectDelegate OnConnect;

        /// <summary>
        /// pipe terminal list
        /// </summary>
        protected List<PipeTerminal> m_termlist = new List<PipeTerminal>();

        /// <summary>
        /// pipe terminal new instance call type
        /// </summary>
        /// <param name="socket"></param>
        /// <param name="disconnectcall"></param>
        /// <returns></returns>
        public delegate PipeTerminal CreatePipeTerminalDelegate(TcpClient tcplient, PipeTerminal.DisconnectCallDelegate disconnectcall);

        /// <summary>
        /// pipe terminal new instance event
        /// </summary>
        public event CreatePipeTerminalDelegate OnCreatePipeTerminal;

        /// <summary>
        /// Start logic
        /// </summary>
        public void Start()
        {
            m_listner.Start();

            new Thread(() =>
            {
                bool bKeep = false;

                while(bKeep == true || m_terminate.WaitOne(100) == false )
                {
                    if (m_listner.Pending() == true)
                    {
                        var tcplient = m_listner.AcceptTcpClient();

                        var term = OnCreatePipeTerminal?.Invoke(tcplient, (targetterm)=> 
                        {
                            lock (m_termlist)
                            {
                                m_termlist.Remove(targetterm);
                                targetterm.Dispose();
                            }
                        });

                        lock (m_termlist)
                        {
                            m_termlist.Add(term);
                        }

                        OnConnect?.Invoke(term);

                        term.Start();

                        bKeep = true;
                    }
                    else
                        bKeep = false;
                }
            }).Start();
        }

        /// <summary>
        /// Send
        /// </summary>
        /// <param name="message"></param>
        public void Send( string message)
        {
            List<PipeTerminal> termlist = null;

            lock (m_termlist)
            {
                termlist = m_termlist.ToList();
            }

            new Thread(() =>
            {
                termlist.ForEach(term => term.Send(message));
            }).Start();
        }

        /// <summary>
        /// NetCat terminal
        /// </summary>
        public class PipeTerminal : IDisposable
        {
            /// <summary>
            /// TCP Client
            /// </summary>
            protected TcpClient m_tcpclient;

            /// <summary>
            /// Disconnect call type
            /// </summary>
            /// <param name="terminal"></param>
            public delegate void DisconnectCallDelegate(PipeTerminal terminal);

            /// <summary>
            /// Disconnect evnet
            /// </summary>
            public event DisconnectCallDelegate OnDisconnect;

            /// <summary>
            /// Receive call type
            /// </summary>
            /// <param name="terminal"></param>
            /// <param name="bin"></param>
            public delegate void ReceiveCallDelegate(PipeTerminal terminal, byte[] bin, int length );

            /// <summary>
            /// Receive event
            /// </summary>
            public event ReceiveCallDelegate OnReceive;

            /// <summary>
            /// Constructor
            /// </summary>
            public PipeTerminal(TcpClient tcplient, DisconnectCallDelegate disconnectcall )
            {
                OnDisconnect += disconnectcall;

                m_tcpclient = tcplient;
            }

            /// <summary>
            /// Start logic
            /// </summary>
            public virtual void Start()
            {
                var socket = m_tcpclient.Client;

                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 500000);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 50000);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, 1);
                LingerOption lingerOption = new LingerOption(true, 1);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Linger, lingerOption);

                new Thread(() =>
                {
                    try
                    {
                        var buffer = new byte[4096];

                        while (true)
                        {
                            if (socket.Poll(1000000, SelectMode.SelectRead) == false)
                            {
                                OnReceive?.Invoke(this, buffer, 0);

                                continue;
                            }

                            var iLen = m_tcpclient.GetStream().Read(buffer);
                            if (iLen <= 0)
                            {
                                OnDisconnect(this);

                                //Disconnect
                                break;
                            }

                            OnReceive?.Invoke(this, buffer, iLen);
                        }
                    }
                    catch { }
                }
                ).Start();
            }

            /// <summary>
            /// Finish
            /// </summary>
            public virtual void Dispose()
            {
                try
                {
                    if (m_tcpclient != null)
                    {
                        m_tcpclient.Close();
                        m_tcpclient.Dispose();

                        m_tcpclient = null;
                    }
                }
                catch { }
            }

            /// <summary>
            /// Send
            /// </summary>
            /// <param name="message"></param>
            public void Send(string message)
            {
                try
                {
                    var memst = new MemoryStream();
                    memst.Write(ASCIIEncoding.ASCII.GetBytes(message));
                    memst.WriteByte(0x0a);

                    m_tcpclient.GetStream().Write(memst.ToArray());
                }
                catch { }
            }
        }
    }
}
