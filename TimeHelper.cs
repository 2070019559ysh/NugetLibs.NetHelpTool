using System;
using System.Collections.Generic;
using System.Text;

namespace NugetLibs.NetHelpTool
{
    /// <summary>
    /// 有关时间相关处理
    /// </summary>
    public class TimeHelper
    {
        /// <summary>
        /// 获取指定时间戳所对应的时间
        /// </summary>
        /// <param name="timestamp">时间戳</param>
        /// <param name="timeStampType">时间戳类型</param>
        /// <returns>实际时间</returns>
        public static DateTime GetDateTime(long timestamp, TimeStampType timeStampType = TimeStampType.Seconds)
        {
            if (timeStampType == TimeStampType.Seconds)
            {
                return new DateTime(1970, 1, 1).AddHours(8).AddSeconds(timestamp);
            }
            else
            {
                return new DateTime(1970, 1, 1).AddHours(8).AddMilliseconds(timestamp);
            }
        }

        /// <summary>
        /// 获取指定时间的时间戳
        /// </summary>
        /// <param name="datetime">指定时间</param>
        /// <param name="timeStampType">所需时间戳类型</param>
        /// <returns>时间戳</returns>
        public static long GetTime(DateTime datetime, TimeStampType timeStampType = TimeStampType.Seconds)
        {
            TimeSpan timeSpan = datetime - new DateTime(1970, 1, 1).AddHours(8);
            if (timeStampType == TimeStampType.Seconds)
            {
                return Convert.ToInt64(timeSpan.TotalSeconds);
            }
            else
            {
                return Convert.ToInt64(timeSpan.TotalMilliseconds);
            }
        }
    }

    /// <summary>
    /// 指示时间戳的精确级别
    /// </summary>
    public enum TimeStampType
    {
        /// <summary>
        /// 秒级
        /// </summary>
        Seconds,
        /// <summary>
        /// 毫秒级
        /// </summary>
        Milliseconds
    }
}
