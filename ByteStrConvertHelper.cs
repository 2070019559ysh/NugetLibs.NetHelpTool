using System;
using System.Collections.Generic;
using System.Text;

namespace NugetLibs.NetHelpTool
{
    /// <summary>
    /// 字节类型与字符串的相互转换帮助类
    /// </summary>
    public static class ByteStrConvertHelper
    {
        /// <summary>  
        /// 转换字符流成字符串  
        /// </summary>  
        /// <param name="bytes">字符串的Byte数组</param>  
        /// <returns>原字符串</returns>  
        public static string ToString(byte[] bytes)
        {
            var sb = new StringBuilder(64);
            foreach (byte iByte in bytes) sb.AppendFormat("{0:x2}", iByte);
            return sb.ToString();
        }

        /// <summary>  
        /// 转换成Byte数组  
        /// </summary>  
        /// <param name="hexString">需转Byte数组的原字符串</param>  
        /// <returns>Byte数组</returns>  
        public static byte[] ToBytes(string hexString)
        {
            if (hexString == null) return null;
            var data = new byte[hexString.Length / 2];
            int h, l;
            for (var i = 0; i < data.Length; i++)
            {
                h = (hexString[2 * i] > 57 ? hexString[2 * i] - 'A' + 10 : hexString[2 * i] - '0') << 4 & 0x000000F0;
                l = (hexString[2 * i + 1] > 57 ? hexString[2 * i + 1] - 'A' + 10 : hexString[2 * i + 1] - '0') & 0x0000000F;

                data[i] = (byte)(h | l);
            }

            return data;
        }
    }
}
