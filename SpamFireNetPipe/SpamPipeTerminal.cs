using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SpamFireNetPipe
{
    /// <summary>
    /// Spam terminal
    /// </summary>
    public class SpamPipeTerminal : netcatserver.PipeTerminal
    {
        /// <summary>
        /// Receive stream
        /// </summary>
        public MemoryStream ReceiveStream = new MemoryStream();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="tcplient"></param>
        /// <param name="disconnectcall"></param>
        public SpamPipeTerminal(TcpClient tcplient, DisconnectCallDelegate disconnectcall):base(tcplient, disconnectcall)
        {
        }

        /// <summary>
        /// force timeout timer
        /// </summary>
        protected System.Threading.Timer m_jobover_timer;

        /// <summary>
        /// Start logic
        /// </summary>
        public override void Start()
        {
            base.Start();

            m_jobover_timer = new System.Threading.Timer((sts) =>
            {
                Dispose();
            }, null, 60000, System.Threading.Timeout.Infinite);
        }

        /// <summary>
        /// Finish
        /// </summary>
        public override void Dispose()
        {
            try
            {
                if (m_jobover_timer != null)
                {
                    m_jobover_timer.Dispose();
                    m_jobover_timer = null;
                }
            }
            catch { }

            base.Dispose();
        }
    }
}
