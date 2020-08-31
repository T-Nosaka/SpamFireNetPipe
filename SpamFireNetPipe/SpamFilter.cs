﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

using Newtonsoft.Json;
using HtmlAgilityPack;
using Newtonsoft.Json.Linq;

namespace SpamAttack
{
    /// <summary>
    /// SpamFilter
    /// </summary>
    public class SpamFilter
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public SpamFilter()
        {
        }

        /// <summary>
        /// Clear Cache
        /// </summary>
        public virtual void CacheClear()
        {
            lock (m_blackresultlist)
            {
                m_blackresultlist.Clear();
            }
            lock (m_dnsblwhitelist)
            {
                m_dnsblwhitelist.Clear();
            }
        }

        /// <summary>
        /// Cache Over
        /// </summary>
        public virtual void CacheOver( long overvalue )
        {
            var nowticks = DateTime.Now.Ticks;

            lock (m_blackresultlist)
            {
                var deletelist = (from rec in m_blackresultlist
                                  where rec.Value < (nowticks - overvalue)
                                  select rec.Key).ToList();
                deletelist.ForEach(rec => m_blackresultlist.Remove(rec));
            }

            lock (m_dnsblwhitelist)
            {
                var deletelist = (from rec in m_dnsblwhitelist
                                  where rec.Value < (nowticks - overvalue)
                                  select rec.Key).ToList();
                deletelist.ForEach(rec => m_dnsblwhitelist.Remove(rec));
            }
        }

        /// <summary>
        /// Export black and white list
        /// </summary>
        /// <returns></returns>
        public virtual void ExportList(StreamWriter sw)
        {
            var exp = new {
                blacklist =JToken.FromObject(m_blackresultlist),
                dnswhitelist = JToken.FromObject(m_dnsblwhitelist),
            };

            sw.Write(JsonConvert.SerializeObject(exp));
        }

        /// <summary>
        /// Import black and white list
        /// </summary>
        /// <param name="sr"></param>
        public virtual void ImportList(StreamReader sr)
        {
            var imp = JsonConvert.DeserializeObject(sr.ReadToEnd()) as JObject;

            foreach(JProperty prop in imp["blacklist"] )
                m_blackresultlist[prop.Name] = long.Parse(prop.Value.ToString());

            foreach (JProperty prop in imp["dnswhitelist"])
                m_dnsblwhitelist[prop.Name] = long.Parse(prop.Value.ToString());
        }

        /// <summary>
        /// Judgment
        /// </summary>
        public bool Fire(MimeKit.MimeMessage mail)
        {
            bool bDnsBL = false;
            try
            {
                Console.WriteLine($"{mail.Subject} {mail.To[0].ToString()}");
#if DEBUG
                foreach( var record in mail.Headers )
                {
                    Console.WriteLine($"{record.Field}:{record.Value}");
                }
#endif

                //Analyzing Received in header
                var rsvstr = string.Empty;
                var receivelist = mail.Headers.Where(head => head.Id == MimeKit.HeaderId.Received).ToList();
                foreach (var head in receivelist)
                {
                    if (bDnsBL == true)
                        break;

                    var address = AnalyzedReceived(head.Value);
                    if (address != string.Empty && bDnsBL == false)
                    {
                        bDnsBL = DNSBL(address);
                    }

                    rsvstr += $"[{address}]";
                }

                if (bDnsBL == false)
                {
                    //Content analysis
                    if (mail.Body is MimeKit.TextPart)
                    {
                        if ((mail.Body as MimeKit.TextPart).IsHtml)
                            bDnsBL = AnalyzaHTML((mail.Body as MimeKit.TextPart).Text);
                    }
                    if (bDnsBL == false)
                    {
                        if (mail.Body is MimeKit.Multipart)
                        {
                            foreach (var body in (mail.Body as MimeKit.Multipart))
                            {
                                if (body is MimeKit.TextPart)
                                {
                                    if ((body as MimeKit.TextPart).IsHtml)
                                        bDnsBL = AnalyzaHTML((body as MimeKit.TextPart).Text);
                                    if (bDnsBL == true)
                                        break;
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            
            return bDnsBL;
        }

        /// <summary>
        /// Incoming server analysis
        /// </summary>
        /// <param name="val"></param>
        /// <returns></returns>
        protected string AnalyzedReceived(string val)
        {
            try
            {
                var result = string.Empty;

                string targetstr = string.Empty;
                var esplitlist = val.Split(' ');
                var bFind = false;
                foreach (var tk in esplitlist)
                {
                    if (bFind == true)
                    {
                        if (tk.IndexOf(".") > 0)
                        {
                            targetstr = tk;
                            break;
                        }
                        bFind = false;
                    }
                    switch (tk.ToLower())
                    {
                        case "by":
                        case "from":
                        case "server":
                        case "id":
                            bFind = true;
                            break;
                    }
                }
                if (targetstr == string.Empty)
                    targetstr = val;
                else
                    result = targetstr;

                var f = targetstr.IndexOf('[');
                if (f >= 0)
                {
                    var e = targetstr.IndexOf(']', f + 1);
                    result = targetstr.Substring(f + 1, e - f - 1);
                    targetstr = result;
                }

                f = targetstr.IndexOf('(');
                if (f >= 0)
                {
                    var e = targetstr.IndexOf(')', f + 1);
                    result = targetstr.Substring(f + 1, e - f - 1);
                    targetstr = result;
                }

                if (result.IndexOf("HELO ") == 0)
                {
                    var s = result.Split(' ');
                    result = s[1];
                }

                if (result.IndexOf(",") >= 0 || result.IndexOf("@") >= 0)
                {
                    foreach (var s in val.Split(' '))
                    {
                        if (s.Contains("."))
                        {
                            try
                            {
                                var uri = new Uri($"{Uri.UriSchemeHttp}{Uri.SchemeDelimiter}{s}");
                                result = uri.Host;
                                break;
                            }
                            catch { }
                        }
                    }
                }

                return result;
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Black result cache
        /// </summary>
        protected Dictionary<string, long> m_blackresultlist = new Dictionary<string, long>();

        /// <summary>
        /// DNSBL list server
        /// </summary>
        protected List<string> m_blacklist = new List<string>();

        /// <summary>
        /// Add DNSBL server
        /// </summary>
        /// <param name="dnsblackserver"></param>
        public void AddDNSBL( string dnsblackserver )
        {
            m_blacklist.Add(dnsblackserver);
        }

        /// <summary>
        /// DNSBL Whitelist
        /// </summary>
        protected Dictionary<string, long> m_dnsblwhitelist = new Dictionary<string, long>();

        /// <summary>
        /// Check blacklist by DNSBL
        /// </summary>
        /// <param name="address"></param>
        /// <param name="blacklist"></param>
        /// <returns></returns>
        protected bool DNSBL(string address)
        {
            lock (m_blackresultlist)
            {
                if (m_blackresultlist.ContainsKey(address) == true)
                    return true;
            }
            lock(m_dnsblwhitelist)
            {
                if (m_dnsblwhitelist.ContainsKey(address) == true)
                    return false;
            }

            foreach (var blsrv in m_blacklist)
            {
                var result = DNSBLInner(address, blsrv);
                if (result == true)
                {
                    lock (m_blackresultlist)
                    {
                        m_blackresultlist[address] = DateTime.Now.Ticks;
                        return true;
                    }
                }
            }

            lock (m_dnsblwhitelist)
            {
                m_dnsblwhitelist[address] = DateTime.Now.Ticks;
            }

            return false;
        }

        /// <summary>
        /// Check blacklist by DNSBL
        /// Implementation
        /// </summary>
        /// <param name="address"></param>
        /// <param name="blacklist"></param>
        /// <returns></returns>

        protected bool DNSBLInner(string address, string blacklist)
        {
            //Check IPv4
            IPAddress ipv4 = null;
            try
            {
                ipv4 = IPAddress.Parse(address);
            }
            catch { }

            string hostName = string.Empty;

            if (ipv4 == null)
            {
                try
                {
                    var iplist = Dns.GetHostAddresses(address);
                    if (iplist == null)
                        return true;

                    ipv4 = iplist.Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).First();
                }
                catch (System.Net.Sockets.SocketException ex)
                {
                    if (ex.NativeErrorCode == 11001)
                        return true;
                    else
                        return false;
                }
            }
            if (ipv4 == null)
                return true;

            try
            {
                string ipAddressReversed = String.Join(".", ipv4.GetAddressBytes().Reverse());
                hostName = String.Concat(ipAddressReversed, ".", blacklist);

                foreach (IPAddress hostAddress in Dns.GetHostAddresses(hostName))
                {
                    if (IPAddress.IsLoopback(hostAddress))
                    {
                        Console.WriteLine($"DNSBL({blacklist}):{address}");

                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Custom black reference url link
        /// </summary>
        protected List<string> m_blackurl_custom_list = new List<string>();

        /// <summary>
        /// Add Custom black reference url link
        /// </summary>
        /// <param name="url"></param>
        public void AddCustomURLLink(string url )
        {
            m_blackurl_custom_list.Add(url);
        }

        /// <summary>
        /// Measures Href Double quote
        /// </summary>
        /// <param name="href"></param>
        /// <returns></returns>
        protected string HrefStrip(string href)
        {
            //Measures Double quote
            if (href.Length > 0)
            {
                if (href[0] == '"' && href[href.Length - 1] == '"')
                {
                    return href.Substring(1, href.Length - 2);
                }
            }
            return href;
        }

        /// <summary>
        /// Analyze HTML callback type
        /// </summary>
        /// <param name="targethref"></param>
        /// <returns></returns>
        protected delegate bool OnHrefAnalyzaHTMLDelegate(string targethref);

        /// <summary>
        /// Analyze HTML
        /// </summary>
        /// <param name="html"></param>
        protected virtual bool AnalyzaHTML(string html, OnHrefAnalyzaHTMLDelegate hrefcallback = null)
        {
            HtmlAgilityPack.HtmlDocument doc = new HtmlAgilityPack.HtmlDocument();
            doc.LoadHtml(html);

            var anodecollection = doc.DocumentNode.SelectNodes("//a");
            HtmlNode anode = null;
            if (anodecollection != null)
                anode = anodecollection[0];
            while (anode != null)
            {
                var reftext = anode.Attributes["href"];
                if (reftext != null)
                {
                    try
                    {
                        var targeturl = HrefStrip(reftext.Value);
                        var host = new Uri(targeturl).Host;
                        if (DNSBL(host) == true)
                            return true;

                        //Custom static url
                        if (m_blackurl_custom_list.Any(word => host.IndexOf(word) >= 0) == true)
                            return true;

                        //Custom dynamic url
                        if (hrefcallback?.Invoke(targeturl) == true)
                            return true;
                    }
                    catch { }
                }

                anode = anode.NextSibling;
            }

            return false;
        }
    }
}
