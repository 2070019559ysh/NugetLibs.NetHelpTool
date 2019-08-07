using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace NugetLibs.NetHelpTool
{
    /// <summary>
    /// 获取客户端IP地址帮助类
    /// </summary>
    public static class IPHelper
    {
        /// <summary>
        /// 获取客户端IP地址
        /// </summary>
        /// <returns>若失败则返回回送地址</returns>
        public static string GetIP()
        {
            string result = String.Empty;
            try
            {
                result = HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

                //可能有代理   
                if (!string.IsNullOrWhiteSpace(result))
                {
                    //没有"." 肯定是非IP格式  
                    if (result.IndexOf(".") == -1)
                    {
                        result = null;
                    }
                    else
                    {
                        //有","，估计多个代理。取第一个不是内网的IP。  
                        if (result.IndexOf(",") != -1)
                        {
                            result = result.Replace(" ", string.Empty).Replace("\"", string.Empty);

                            string[] temparyip = result.Split(",;".ToCharArray());

                            if (temparyip != null && temparyip.Length > 0)
                            {
                                for (int i = 0; i < temparyip.Length; i++)
                                {
                                    //找到不是内网的地址  
                                    if (IsIP(temparyip[i]) && temparyip[i].Substring(0, 3) != "10." && temparyip[i].Substring(0, 7) != "192.168" && temparyip[i].Substring(0, 7) != "172.16.")
                                    {
                                        return temparyip[i];
                                    }
                                }
                            }
                        }
                        //代理即是IP格式  
                        else if (IsIP(result))
                        {
                            return result;
                        }
                        //代理中的内容非IP  
                        else
                        {
                            result = null;
                        }
                    }
                }
                if (string.IsNullOrEmpty(result))
                {
                    result = HttpContext.Current.Request.UserHostAddress;
                }
            }
            catch
            {
                try
                {
                    string hostName = Dns.GetHostName(); //得到主机名  
                    IPHostEntry IpEntry = Dns.GetHostEntry(hostName);
                    for (int i = 0; i < IpEntry.AddressList.Length; i++)
                    {
                        //从IP地址列表中筛选出IPv4类型的IP地址  
                        //AddressFamily.InterNetwork表示此IP为IPv4,  
                        //AddressFamily.InterNetworkV6表示此地址为IPv6类型  
                        if (IpEntry.AddressList[i].AddressFamily == AddressFamily.InterNetwork)
                        {
                            result = IpEntry.AddressList[i].ToString();
                            break;
                        }
                    }
                }
                catch { }
            }
            if (string.IsNullOrWhiteSpace(result)) result = "127.0.0.1";
            return result;
        }

        /// <summary>
        /// 判断字符串是否是个IP地址
        /// </summary>
        /// <param name="str">可能是IP地址的字符串</param>
        /// <returns>是否是个IP地址</returns>
        public static bool IsIP(string str)
        {
            if (string.IsNullOrWhiteSpace(str) || str.Length < 7 || str.Length > 15)
                return false;
            string regformat = @"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})";
            Regex regex = new Regex(regformat, RegexOptions.IgnoreCase);
            return regex.IsMatch(str);
        }
    }
}
