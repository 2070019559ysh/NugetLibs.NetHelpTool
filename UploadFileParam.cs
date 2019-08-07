using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NugetLibs.NetHelpTool
{
    /// <summary>
    /// 上传文件 - 请求参数类
    /// </summary>
    public class UploadFileParam
    {

        /// <summary>
        /// 上传地址
        /// </summary>
        public string Url { get; set; }
        /// <summary>
        /// 文件名称key
        /// </summary>
        public string FileNameKey { get; set; }
        /// <summary>
        /// 文件名称value
        /// </summary>
        public string FileNameValue { get; set; }
        /// <summary>
        /// 编码格式
        /// </summary>
        public Encoding Encoding { get; set; }
        /// <summary>
        /// 上传文件的流
        /// </summary>
        public Stream FileStream { get; set; }
        /// <summary>
        /// 上传文件 携带的参数集合
        /// </summary>
        public IDictionary<string, string> PostParameters { get; set; }

        /// <summary>
        /// 需指定必须的上传地址、文件名称、文件流的唯一实例化构造函数
        /// </summary>
        /// <param name="url">上传地址</param>
        /// <param name="fileNameValue">文件名称，建议使用Path.GetFileName(filePath)</param>
        /// <param name="fileStream">文件流</param>
        public UploadFileParam(string url, string fileNameValue, Stream fileStream)
        {
            FileNameKey = "fileName";
            Encoding = Encoding.UTF8;
            PostParameters = new Dictionary<string, string>();
            this.Url = url;
            this.FileNameValue = fileNameValue;
            this.FileStream = fileStream;
        }
    }
}
