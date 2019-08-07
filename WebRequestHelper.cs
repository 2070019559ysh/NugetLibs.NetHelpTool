using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace NugetLibs.NetHelpTool
{
    /// <summary>
    /// 提供Web请求的帮助类
    /// </summary>
    public class WebRequestHelper
    {
        /// <summary>
        /// 发送Get请求并返回响应字符串
        /// </summary>
        /// <param name="url">请求Url，如：http://yshweb.wicp.net/Home?lg=zh-cn </param>
        /// <param name="headers">添加请求头参数的集合</param>
        /// <returns>响应字符串</returns>
        public static string HttpGet(string url, NameValueCollection headers = null)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            if (headers != null)
                request.Headers.Add(headers);
            request.Method = "GET";
            request.ContentType = "text/html;charset=UTF-8";
            return GetResponse(request);
        }

        /// <summary>
        /// 发送Get请求并返回响应结果对象
        /// </summary>
        /// <param name="url">请求Url，如：http://yshweb.wicp.net/Home?lg=zh-cn </param>
        /// <param name="headers">添加请求头参数的集合</param>
        /// <returns>响应结果对象</returns>
        public static T HttpGet<T>(string url, NameValueCollection headers = null)
        {
            string resultStr = HttpGet(url, headers);
            T result = JsonConvert.DeserializeObject<T>(resultStr);
            return result;
        }

        /// <summary>
        /// 根据HttpWebRequest请求对象获取最终响应信息
        /// </summary>
        /// <param name="request">HttpWebRequest请求对象</param>
        /// <returns>响应字符串信息</returns>
        private static string GetResponse(HttpWebRequest request)
        {
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream myResponseStream = response.GetResponseStream();
            StreamReader myStreamReader = new StreamReader(myResponseStream, Encoding.GetEncoding("UTF-8"));
            string retString = myStreamReader.ReadToEnd();
            myStreamReader.Dispose();
            myResponseStream.Dispose();
            return retString;
        }

        /// <summary>
        /// 利用HttpClient进行GET请求
        /// </summary>
        /// <param name="url">请求Url，如：http://yshweb.wicp.net/Home?lg=zh-cn </param>
        /// <param name="isDecompress">是否需要解压，默认false</param>
        /// <returns>响应字符串</returns>
        public static string HttpClientGet(string url, bool isDecompress = false)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("UserAgent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36");
                client.DefaultRequestHeaders.Add("Timeout", 30.ToString());
                client.DefaultRequestHeaders.Add("KeepAlive", "true");

                Task<HttpResponseMessage> responseMsgTask = client.GetAsync(url);
                responseMsgTask.Wait();
                string responseMsg;
                if (isDecompress)
                {
                    Task<Stream> responseStream = responseMsgTask.Result.Content.ReadAsStreamAsync();
                    GZipStream deZipStream = new GZipStream(responseStream.Result, CompressionMode.Decompress);
                    StreamReader myStreamReader = new StreamReader(deZipStream, Encoding.UTF8);
                    responseMsg = myStreamReader.ReadToEnd();
                }
                else
                {
                    Task<byte[]> responseContent = responseMsgTask.Result.Content.ReadAsByteArrayAsync();
                    responseMsg = Encoding.UTF8.GetString(responseContent.Result);
                }
                return responseMsg;
            }
        }

        /// <summary>
        /// 利用HttpClient进行GET请求
        /// </summary>
        /// <param name="url">请求Url，如：http://yshweb.wicp.net/Home?lg=zh-cn </param>
        /// <param name="isDecompress">是否需要解压，默认false</param>
        /// <returns>响应结果对象</returns>
        public static T HttpClientGet<T>(string url, bool isDecompress = false)
        {
            string resultStr = HttpClientGet(url, isDecompress);
            T result = JsonConvert.DeserializeObject<T>(resultStr);
            return result;
        }

        /// <summary>
        /// 发送Post请求
        /// </summary>
        /// <param name="url">请求Url</param>
        /// <param name="body">请求参数</param>
        /// <param name="contentType">请求内容类型，可设置为application/x-www-form-urlencoded</param>
        /// <param name="headers">添加请求头参数的集合</param>
        /// <returns>响应字符串</returns>
        public static string PostHttp(string url, object body, string contentType = "application/json", NameValueCollection headers = null)
        {
            string requestData = JsonConvert.SerializeObject(body);
            using (HttpClient client = new HttpClient())
            {
                byte[] dataArray = Encoding.UTF8.GetBytes(requestData);
                MemoryStream ms = new MemoryStream(dataArray.Length);
                ms.Write(dataArray, 0, dataArray.Length);
                ms.Position = 0;
                //ms.Seek(0, SeekOrigin.Begin);//设置指针读取位置
                HttpContent hc = new StreamContent(ms);

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml", 0.9));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("image/webp"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.8));
                hc.Headers.Add("UserAgent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36");
                hc.Headers.Add("Timeout", 30.ToString());
                hc.Headers.Add("KeepAlive", "true");
                if (headers != null)
                {
                    for(int i=0;i< headers.Count; i++)
                    {
                        string key = headers.GetKey(i);
                        hc.Headers.Add(key, headers[key]);
                    }
                }
                hc.Headers.ContentType = new MediaTypeHeaderValue(contentType);

                Task<HttpResponseMessage> responseMsgTask = client.PostAsync(url, hc);
                responseMsgTask.Wait();
                Task<byte[]> responseContent = responseMsgTask.Result.Content.ReadAsByteArrayAsync();
                string responseMsg = Encoding.UTF8.GetString(responseContent.Result);
                ms.Close();
                return responseMsg;
            }
        }

        /// <summary>
        /// 发送Post请求
        /// </summary>
        /// <typeparam name="T">响应对象类型</typeparam>
        /// <param name="url">请求Url</param>
        /// <param name="body">请求参数</param>
        /// <param name="contentType">请求内容类型，可设置为application/x-www-form-urlencoded</param>
        /// <param name="headers">添加请求头参数的集合</param>
        /// <returns>响应对象</returns>
        public static T PostHttp<T>(string url, object body, string contentType = "application/json", NameValueCollection headers = null)
        {
            string requestData = JsonConvert.SerializeObject(body);
            using (HttpClient client = new HttpClient())
            {
                byte[] dataArray = Encoding.UTF8.GetBytes(requestData);
                MemoryStream ms = new MemoryStream(dataArray.Length);
                ms.Write(dataArray, 0, dataArray.Length);
                ms.Position = 0;
                //ms.Seek(0, SeekOrigin.Begin);//设置指针读取位置
                HttpContent hc = new StreamContent(ms);

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml", 0.9));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("image/webp"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.8));
                hc.Headers.Add("UserAgent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36");
                hc.Headers.Add("Timeout", 30.ToString());
                hc.Headers.Add("KeepAlive", "true");
                if (headers != null)
                {
                    for (int i = 0; i < headers.Count; i++)
                    {
                        string key = headers.GetKey(i);
                        hc.Headers.Add(key, headers[key]);
                    }
                }
                hc.Headers.ContentType = new MediaTypeHeaderValue(contentType);

                Task<HttpResponseMessage> responseMsgTask = client.PostAsync(url, hc);
                responseMsgTask.Wait();
                Task<byte[]> responseContent = responseMsgTask.Result.Content.ReadAsByteArrayAsync();
                string responseMsg = Encoding.UTF8.GetString(responseContent.Result);
                try
                {
                    T responseObj = JsonConvert.DeserializeObject<T>(responseMsg);
                    return responseObj;
                }
                catch (JsonReaderException ex)
                {
                    throw new JsonReaderException("请求远程响应内容异常：" + responseMsg + "；" + ex.Message);
                }
                catch (Exception ex)
                {
                    ex.Data.Add("ResponseMsg", responseMsg);//外面可以读取响应的原字符串
                    throw ex;
                }
                finally
                {
                    ms.Close();
                }
            }
        }

        /// <summary>
        /// 以表单形式发送Post请求
        /// </summary>
        /// <typeparam name="T">响应对象类型</typeparam>
        /// <param name="url">请求Url</param>
        /// <param name="body">请求参数</param>
        /// <returns>响应对象</returns>
        public static T FormPostHttp<T>(string url, IEnumerable<KeyValuePair<string, string>> body)
        {
            using (HttpClient client = new HttpClient())
            {
                using (FormUrlEncodedContent formUrlEncodedContent = new FormUrlEncodedContent(body))
                {
                    Task<HttpResponseMessage> responseMsgTask = client.PostAsync(url, formUrlEncodedContent);
                    responseMsgTask.Wait();
                    Task<byte[]> responseContent = responseMsgTask.Result.Content.ReadAsByteArrayAsync();
                    string responseMsg = Encoding.UTF8.GetString(responseContent.Result);
                    try
                    {
                        T responseObj = JsonConvert.DeserializeObject<T>(responseMsg);
                        return responseObj;
                    }
                    catch (JsonReaderException ex)
                    {
                        throw new JsonReaderException("请求远程响应内容异常：" + responseMsg + "；" + ex.Message);
                    }
                    catch (Exception ex)
                    {
                        ex.Data.Add("ResponseMsg", responseMsg);//外面可以读取响应的原字符串
                        throw ex;
                    }
                }
            }
        }

        /// <summary>
        /// 上传文件
        /// </summary>
        /// <param name="parameter">包含文件二进制数据的上传参数</param>
        /// <returns>上传后的响应结果</returns>
        public static string UploadFile(UploadFileParam parameter)
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                // 1.分界线
                string boundary = string.Format("----{0}", DateTime.Now.Ticks.ToString("x")),       // 分界线可以自定义参数
                    beginBoundary = string.Format("--{0}\r\n", boundary),
                    endBoundary = string.Format("\r\n--{0}--\r\n", boundary);
                byte[] beginBoundaryBytes = parameter.Encoding.GetBytes(beginBoundary),
                    endBoundaryBytes = parameter.Encoding.GetBytes(endBoundary);
                // 2.组装开始分界线数据体 到内存流中
                memoryStream.Write(beginBoundaryBytes, 0, beginBoundaryBytes.Length);
                // 3.组装 上传文件附加携带的参数 到内存流中
                if (parameter.PostParameters != null && parameter.PostParameters.Count > 0)
                {
                    foreach (KeyValuePair<string, string> keyValuePair in parameter.PostParameters)
                    {
                        string parameterHeaderTemplate = string.Format("Content-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}\r\n{2}", keyValuePair.Key, keyValuePair.Value, beginBoundary);
                        byte[] parameterHeaderBytes = parameter.Encoding.GetBytes(parameterHeaderTemplate);

                        memoryStream.Write(parameterHeaderBytes, 0, parameterHeaderBytes.Length);
                    }
                }
                // 4.组装文件头数据体 到内存流中
                string fileHeaderTemplate = string.Format("Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\nContent-Type: application/octet-stream\r\n\r\n", parameter.FileNameKey, parameter.FileNameValue);
                byte[] fileHeaderBytes = parameter.Encoding.GetBytes(fileHeaderTemplate);
                memoryStream.Write(fileHeaderBytes, 0, fileHeaderBytes.Length);
                // 5.组装文件流 到内存流中
                byte[] buffer = new byte[1024 * 1024 * 1];
                int size = parameter.FileStream.Read(buffer, 0, buffer.Length);
                while (size > 0)
                {
                    memoryStream.Write(buffer, 0, size);
                    size = parameter.FileStream.Read(buffer, 0, buffer.Length);
                }
                // 6.组装结束分界线数据体 到内存流中
                memoryStream.Write(endBoundaryBytes, 0, endBoundaryBytes.Length);
                // 7.获取二进制数据
                byte[] postBytes = memoryStream.ToArray();
                // 8.HttpWebRequest 组装
                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(new Uri(parameter.Url, UriKind.RelativeOrAbsolute));
                webRequest.Method = "POST";
                webRequest.Timeout = int.MaxValue;
                webRequest.ContentType = string.Format("multipart/form-data; boundary={0}", boundary);
                webRequest.ContentLength = postBytes.Length;
                if (Regex.IsMatch(parameter.Url, "^https://"))
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
                    ServicePointManager.ServerCertificateValidationCallback = CheckValidationResult;
                }
                // 9.写入上传请求数据
                using (Stream requestStream = webRequest.GetRequestStream())
                {
                    requestStream.Write(postBytes, 0, postBytes.Length);
                    requestStream.Close();
                }
                // 10.获取响应
                using (HttpWebResponse webResponse = (HttpWebResponse)webRequest.GetResponse())
                {
                    using (StreamReader reader = new StreamReader(webResponse.GetResponseStream(), parameter.Encoding))
                    {
                        string body = reader.ReadToEnd();
                        reader.Close();
                        return body;
                    }
                }
            }
        }

        private static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        /// <summary>
        /// 下载文件
        /// </summary>
        /// <param name="url">请求下载地址</param>
        /// <param name="filePathName">下载保存的包含路径的文件名，注意以最终返回文件名为准</param>
        /// <returns>保存的包含路径的文件名</returns>
        public static string DownloadFile(string url, string filePathName)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.ContentType.Equals("text/plain"))
                {
                    //下载多媒体文件失败
                    string address = response.ResponseUri.ToString();
                    WebClient mywebclient = new WebClient();
                    byte[] dataContent = mywebclient.DownloadData(address);
                    MemoryStream stream = new MemoryStream(dataContent);
                    StreamReader streamReader = new StreamReader(stream);
                    string resultData = streamReader.ReadToEnd();
                    streamReader.Close();
                    stream.Close();
                    throw new Exception(resultData);
                }
                else
                {
                    //下载多媒体文件成功
                    string contentDisposition = response.Headers.Get("Content-disposition");
                    int firstIndex = contentDisposition.IndexOf("filename=") + 9;
                    string downloadFileName = contentDisposition.Substring(firstIndex);
                    downloadFileName = downloadFileName.Trim('"');
                    string fileExtension = Path.GetExtension(downloadFileName);
                    string fileName = Path.GetFileNameWithoutExtension(filePathName);
                    string filePath = Path.GetDirectoryName(filePathName);
                    if (!Directory.Exists(filePath)) Directory.CreateDirectory(filePath);
                    //最终确定的文件名
                    if (Path.GetFileNameWithoutExtension(downloadFileName).Length > 10)
                        filePathName = filePath + "\\" + downloadFileName.Substring(0, 10) + fileExtension;
                    else
                        filePathName = filePath + "\\" + downloadFileName;
                    //先以下载下来的文件名命名；如果已存在，则以前面命名；如果还存在，最后以Guid自动生成命名
                    if (File.Exists(filePathName))
                    {
                        filePathName = filePath + "\\" + fileName + fileExtension;
                    }
                    if (File.Exists(filePathName))
                    {
                        filePathName = filePath + "\\" + Guid.NewGuid().ToString("N") + fileExtension;
                    }
                    string address = response.ResponseUri.ToString();
                    WebClient mywebclient = new WebClient();
                    mywebclient.DownloadFile(address, filePathName);
                    return filePathName;
                }
            }
        }

        /// <summary>
        /// 以POST请求方式下载文件
        /// </summary>
        /// <param name="url">请求下载地址</param>
        /// <param name="filePathName">下载保存的包含路径的文件名，注意以最终返回文件名为准</param>
        /// <param name="postObj">需要Post的数据</param>
        /// <param name="contentType">请求参数内容类型，可以设为application/json</param>
        /// <returns>保存的包含路径的文件名</returns>
        public static string DownloadFilePost(string url, string filePathName, object postObj, string contentType = "application/x-www-form-urlencoded")
        {
            ServicePointManager.Expect100Continue = false;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = contentType;
            string postDataStr = JsonConvert.SerializeObject(postObj);
            byte[] dataBytes = Encoding.UTF8.GetBytes(postDataStr);
            request.ContentLength = dataBytes.Length;
            using (Stream myRequestStream = request.GetRequestStream())
            {
                myRequestStream.Write(dataBytes, 0, dataBytes.Length);
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    if (response.ContentType.Equals("text/plain"))
                    {
                        //下载多媒体文件失败
                        string address = response.ResponseUri.ToString();
                        WebClient mywebclient = new WebClient();
                        byte[] dataContent = mywebclient.DownloadData(address);
                        MemoryStream stream = new MemoryStream(dataContent);
                        StreamReader streamReader = new StreamReader(stream);
                        string resultData = streamReader.ReadToEnd();
                        streamReader.Close();
                        stream.Close();
                        throw new Exception(resultData);
                    }
                    else
                    {
                        //下载多媒体文件成功
                        string contentDisposition = response.Headers.Get("Content-disposition");
                        int firstIndex = contentDisposition.IndexOf("filename=") + 9;
                        string downloadFileName = contentDisposition.Substring(firstIndex);
                        downloadFileName = downloadFileName.Trim('"');
                        string fileExtension = Path.GetExtension(downloadFileName);
                        string fileName = Path.GetFileNameWithoutExtension(filePathName);
                        string filePath = Path.GetDirectoryName(filePathName);
                        if (!Directory.Exists(filePath)) Directory.CreateDirectory(filePath);
                        //最终确定的文件名
                        if (Path.GetFileNameWithoutExtension(downloadFileName).Length > 10)
                            filePathName = filePath + "\\" + downloadFileName.Substring(0, 10) + fileExtension;
                        else
                            filePathName = filePath + "\\" + downloadFileName;
                        //先以下载下来的文件名命名；如果已存在，则以前面命名；如果还存在，最后以Guid自动生成命名
                        if (File.Exists(filePathName))
                        {
                            filePathName = filePath + "\\" + fileName + fileExtension;
                        }
                        if (File.Exists(filePathName))
                        {
                            filePathName = filePath + "\\" + Guid.NewGuid().ToString("N") + fileExtension;
                        }
                        string address = response.ResponseUri.ToString();
                        WebClient mywebclient = new WebClient();
                        mywebclient.DownloadFile(address, filePathName);
                        return filePathName;
                    }
                }
            }
        }
    }
}
