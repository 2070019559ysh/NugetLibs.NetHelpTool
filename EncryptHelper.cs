using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NugetLibs.NetHelpTool
{
    /// <summary>
    /// 加解密帮助类
    /// </summary>
    public class EncryptHelper
    {
        #region 默认密钥定义  
        /// <summary>  
        /// 默认加密密钥  
        /// </summary>  
        public const string DefaultDESKey = @"12345678";
        /// <summary>  
        /// 默认加密向量  
        /// </summary>  
        public const string DefaultDESIV = @"1234567812345678";
        /// <summary>  
        /// 默认加密密钥  
        /// </summary>  
        public const string Default3DESKey = @"123456781234567812345678";
        /// <summary>  
        /// 默认加密向量  
        /// </summary>  
        public const string Default3DESIV = @"1234567812345678";
        /// <summary>  
        /// 获取密钥  
        /// </summary>  
        public const string DefaultAESKey = @"12345678123456781234567812345678";
        /// <summary>  
        /// 获取向量  
        /// </summary>  
        public const string DefaultAESIV = @"1234567812345678";
        /// <summary>  
        /// 默认加密密钥  
        /// </summary>  
        public const string DefaultRC2Key = @"1234567812345678";
        /// <summary>  
        /// 默认加密向量  
        /// </summary>  
        public const string DefaultRC2IV = @"1234567812345678";
        /// <summary>  
        /// 默认的RSA公钥  
        /// </summary>  
        public const string DefaultRSAPublicKey = @"<RSAKeyValue>xxx</RSAKeyValue>";
        /// <summary>  
        /// 默认的RSA密钥  
        /// </summary>  
        public const string DefaultRSAPrivateKey = @"<RSAKeyValue>ccc</RSAKeyValue>";
        #endregion

        #region Base64编码和解码
        /// <summary>
        /// 把字符串进行Base64编码
        /// </summary>
        /// <param name="value">字符串</param>
        /// <returns>Base64编码字符串</returns>
        public static string ToBase64String(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// 把字符串进行Base64解码
        /// </summary>
        /// <param name="value">Base64编码字符串</param>
        /// <returns>原字符串</returns>
        public static string UnBase64String(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }
            byte[] bytes = Convert.FromBase64String(value);
            return Encoding.UTF8.GetString(bytes);
        }
        #endregion

        #region 对称加密算法  

        #region 3DES对称加密算法  
        /// <summary>  
        /// 使用指定的128字节的密钥对8字节数组进行3Des加密  
        /// </summary>  
        /// <param name="plainStr">明文字符串</param>  
        /// <param name="key">密钥长度，可以为128（16字节），或是192（24字节）</param>  
        /// <param name="iv">加密向量长度64位以上(8个字节以上)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>已加密的字符串</returns>  
        public static string TripleDESEncrypt(string plainStr, string key = Default3DESKey, string iv = DefaultDESKey, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray = Encoding.UTF8.GetBytes(plainStr);

            string encrypt = null;
            var tdsc = new TripleDESCryptoServiceProvider();
            try
            {
                //加密模式，偏移  
                tdsc.Mode = mode;
                tdsc.Padding = padding;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, tdsc.CreateEncryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                        if (isBase64Code)
                            encrypt = Convert.ToBase64String(mStream.ToArray());
                        else
                            ByteStrConvertHelper.ToString(mStream.ToArray());
                    }
                }
            }
            catch { }
            tdsc.Clear();

            return encrypt;
        }
        /// <summary>  
        /// 使用指定的128字节的密钥对8字节数组进行3Des解密  
        /// </summary>  
        /// <param name="encryptStr">密文字符串</param>  
        /// <param name="key">密钥长度，可以为128（16字节），或是192（24字节）</param>  
        /// <param name="iv">加密向量长度64位以上(8个字节以上)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>已解密的字符串</returns>  
        public static string TripleDESDecrypt(string encryptStr, string key = Default3DESKey, string iv = DefaultDESKey, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray;
            if (isBase64Code)
                byteArray = Convert.FromBase64String(encryptStr);
            else
                byteArray = ByteStrConvertHelper.ToBytes(encryptStr);

            string decrypt = null;
            var tdsc = new TripleDESCryptoServiceProvider();
            try
            {
                tdsc.Mode = mode;
                tdsc.Padding = padding;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, tdsc.CreateDecryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                        decrypt = Encoding.UTF8.GetString(mStream.ToArray());
                    }
                }
            }
            catch { }
            tdsc.Clear();

            return decrypt;
        }
        #endregion

        #region DES对称加密算法  
        /// <summary>  
        /// DES加密  
        /// </summary>  
        /// <param name="plainStr">明文字符串</param>  
        /// <param name="key">加密密钥长度64位(8字节)</param>  
        /// <param name="iv">加密向量长度64位以上(8个字节以上)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>密文</returns>  
        public static string DESEncrypt(string plainStr, string key = DefaultDESKey, string iv = DefaultDESIV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray = Encoding.UTF8.GetBytes(plainStr);

            string encrypt = null;
            var des = new DESCryptoServiceProvider();
            try
            {
                des.Mode = mode;
                des.Padding = padding;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, des.CreateEncryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                        if (isBase64Code)
                            encrypt = Convert.ToBase64String(mStream.ToArray());
                        else
                            ByteStrConvertHelper.ToString(mStream.ToArray());
                    }
                }
            }
            catch { }
            des.Clear();

            return encrypt;
        }

        /// <summary>  
        /// DES解密  
        /// </summary>  
        /// <param name="encryptStr">密文字符串</param>  
        /// <param name="key">加密密钥长度64位(8字节)</param>  
        /// <param name="iv">加密向量长度64位以上(8个字节以上)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>明文</returns>  
        public static string DESDecrypt(string encryptStr, string key = DefaultDESKey, string iv = DefaultDESIV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray;
            if (isBase64Code)
                byteArray = Convert.FromBase64String(encryptStr);
            else
                byteArray = ByteStrConvertHelper.ToBytes(encryptStr);

            string decrypt = null;
            var des = new DESCryptoServiceProvider();
            try
            {
                des.Mode = mode;
                des.Padding = padding;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, des.CreateDecryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                        decrypt = Encoding.UTF8.GetString(mStream.ToArray());
                    }
                }
            }
            catch { }
            des.Clear();

            return decrypt;
        }
        #endregion

        #region AES加密算法  
        /// <summary>  
        /// AES加密  
        /// </summary>  
        /// <param name="plainStr">明文字符串</param>  
        /// <param name="key">加密密钥支持128(16字节)、192(24字节)、256位(32字节)的key</param>  
        /// <param name="iv">加密向量(16到19字节)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>密文</returns>  
        public static string AESEncrypt(string plainStr, string key = DefaultAESKey, string iv = DefaultAESIV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray = Encoding.UTF8.GetBytes(plainStr);

            var encrypts = AESEncrypt(byteArray, key, iv, mode, padding);
            if (isBase64Code)
                return Convert.ToBase64String(encrypts);
            else
                return ByteStrConvertHelper.ToString(encrypts);
        }
        /// <summary>  
        /// AES加密  
        /// </summary>  
        /// <param name="plainbytes">明文字节数组</param>  
        /// <param name="key">加密密钥支持128(16字节)、192(24字节)、256位(32字节)的key</param>  
        /// <param name="iv">加密向量(16到19字节)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>密文</returns>  
        public static byte[] AESEncrypt(byte[] plainbytes, string key = DefaultAESKey, string iv = DefaultAESIV, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray = plainbytes;

            byte[] encrypt = null;
            var aes = Rijndael.Create();
            try
            {
                aes.Padding = padding;
                aes.Mode = mode;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, aes.CreateEncryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                    }
                    encrypt = mStream.ToArray();
                }
            }
            catch { }
            aes.Clear();

            return encrypt;
        }
        /// <summary>  
        /// AES加密  
        /// </summary>  
        /// <param name="plainbytes">明文字节数组</param>  
        /// <param name="key">加密密钥支持128(16字节)、192(24字节)、256位(32字节)的key</param>  
        /// <param name="iv">加密向量(16到19字节)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>密文</returns>  
        public static string AESEncrypt(byte[] plainbytes, string key = DefaultAESKey, string iv = DefaultAESIV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);

            var encrypts = AESEncrypt(plainbytes, key, iv, mode, padding);
            if (isBase64Code)
                return Convert.ToBase64String(encrypts);
            else
                return ByteStrConvertHelper.ToString(encrypts);
        }
        /// <summary>  
        /// AES解密  
        /// </summary>  
        /// <param name="encryptStr">密文字符串</param>  
        /// <param name="key">加密密钥支持128(16字节)、192(24字节)、256位(32字节)的key</param>  
        /// <param name="iv">加密向量(16到19字节)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>明文</returns>  
        public static string AESDecrypt(string encryptStr, string key = DefaultAESKey, string iv = DefaultAESIV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray;
            if (isBase64Code)
                byteArray = Convert.FromBase64String(encryptStr);
            else
                byteArray = ByteStrConvertHelper.ToBytes(encryptStr);

            string decrypt = null;
            var aes = Rijndael.Create();
            try
            {
                aes.Mode = mode;
                aes.Padding = padding;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, aes.CreateDecryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                        decrypt = Encoding.UTF8.GetString(mStream.ToArray());
                    }
                }
            }
            catch { }
            aes.Clear();

            return decrypt;
        }
        /// <summary>  
        /// AES解密  
        /// </summary>  
        /// <param name="encryptStr">密文字符串</param>  
        /// <param name="key">加密密钥支持128(16字节)、192(24字节)、256位(32字节)的key</param>  
        /// <param name="iv">加密向量(16到19字节)</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>明文</returns>  
        public static byte[] AESDecryptToBytes(string encryptStr, string key = DefaultAESKey, string iv = DefaultAESIV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray;
            if (isBase64Code)
                byteArray = Convert.FromBase64String(encryptStr);
            else
                byteArray = ByteStrConvertHelper.ToBytes(encryptStr);

            byte[] decrypt = null;
            var aes = Rijndael.Create();
            try
            {
                aes.Mode = mode;
                aes.Padding = padding;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, aes.CreateDecryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                    }
                    decrypt = mStream.ToArray();
                }
            }
            catch { }
            aes.Clear();

            return decrypt;
        }
        #endregion

        #region RC2加密算法  
        /// <summary>  
        /// RC2加密  
        /// </summary>  
        /// <param name="plainStr">明文字符串</param>  
        /// <param name="key">加密密钥支持40~128长度，可以每8位递增（5到16个长度的字符串）</param>  
        /// <param name="iv">加密向量64位以上（8个字节上去字符串）</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>密文</returns>  
        public static string RC2Encrypt(string plainStr, string key = DefaultRC2Key, string iv = DefaultRC2IV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray = Encoding.UTF8.GetBytes(plainStr);

            string encrypt = null;
            var rc2 = new RC2CryptoServiceProvider();
            try
            {
                rc2.Padding = padding;
                rc2.Mode = mode;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, rc2.CreateEncryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                        if (isBase64Code)
                            encrypt = Convert.ToBase64String(mStream.ToArray());
                        else
                            encrypt = ByteStrConvertHelper.ToString(mStream.ToArray());
                    }
                }
            }
            catch { }
            rc2.Clear();

            return encrypt;
        }

        /// <summary>  
        /// RC2解密  
        /// </summary>  
        /// <param name="encryptStr">明文字符串</param>  
        /// <param name="key">加密密钥支持40~128长度，可以每8位递增（5到16个长度的字符串）</param>  
        /// <param name="iv">加密向量64位以上（8个字节上去字符串）</param>  
        /// <param name="isBase64Code">是否是Base64编码，否则是16进制编码</param>  
        /// <param name="mode">加密模式</param>  
        /// <param name="padding">填充模式</param>  
        /// <returns>明文</returns>  
        public static string RC2Decrypt(string encryptStr, string key = DefaultRC2Key, string iv = DefaultRC2IV, bool isBase64Code = true, CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            byte[] byteArray;
            if (isBase64Code)
                byteArray = Convert.FromBase64String(encryptStr);
            else
                byteArray = ByteStrConvertHelper.ToBytes(encryptStr);

            string decrypt = null;
            var rc2 = new RC2CryptoServiceProvider();
            try
            {
                rc2.Mode = mode;
                rc2.Padding = padding;
                using (var mStream = new MemoryStream())
                {
                    using (var cStream = new CryptoStream(mStream, rc2.CreateDecryptor(bKey, bIV), CryptoStreamMode.Write))
                    {
                        cStream.Write(byteArray, 0, byteArray.Length);
                        cStream.FlushFinalBlock();
                        decrypt = Encoding.UTF8.GetString(mStream.ToArray());
                    }
                }
            }
            catch { }
            rc2.Clear();

            return decrypt;
        }
        #endregion

        #endregion

        #region 哈稀算法  

        #region 获取哈稀散列值  
        /// <summary>  
        /// 使用md5计算散列  
        /// </summary>  
        /// <param name="source">要用MD5算散列的字节数据</param>  
        /// <returns>经过MD5算散列后的数据</returns>  
        public static byte[] Hash(byte[] source)
        {
            if ((source == null) || (source.Length == 0)) throw new ArgumentException("source is not valid");
            var m = MD5.Create();
            return m.ComputeHash(source);
        }
        /// <summary>  
        /// 对传入的明文密码进行Hash加密,密码不能为中文  
        /// </summary>  
        /// <param name="oriPassword">需要加密的明文密码</param>  
        /// <returns>经过Hash加密的密码</returns>  
        public static string HashPassword(string oriPassword)
        {
            if (string.IsNullOrEmpty(oriPassword))
                throw new ArgumentException("oriPassword is valid");

            var acii = new ASCIIEncoding();
            var hashedBytes = Hash(acii.GetBytes(oriPassword));
            return ByteStrConvertHelper.ToString(hashedBytes);
        }
        /// <summary>  
        /// 计算MD5  
        /// </summary>  
        /// <param name="data">要算MD5的字符串</param>  
        /// <param name="isBase64Code">是否是Base64编码</param>  
        /// <returns>MD5字符串</returns>  
        public static string HashMD5(string data, bool isBase64Code = false)
        {
            if (string.IsNullOrEmpty(data)) return "";
            var md5 = new MD5CryptoServiceProvider();
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            bytes = md5.ComputeHash(bytes);
            md5.Clear();
            if (isBase64Code)
                return Convert.ToBase64String(bytes);
            else
                return ByteStrConvertHelper.ToString(bytes);
        }
        /// <summary>
        /// 把字符串进行32位MD5加密
        /// </summary>
        /// <param name="str">要加密的字符串</param>
        /// <returns>加密的字符串</returns>
        public static string HashMD532(string str)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] strByte = Encoding.Default.GetBytes(str);
            byte[] md5Data = md5.ComputeHash(strByte);
            md5.Clear();
            StringBuilder strBuilder = new StringBuilder();
            for (var i = 0; i < md5Data.Length; i++)
            {
                strBuilder.Append(md5Data[i].ToString("x2"));
            }
            return strBuilder.ToString();
        }
        /// <summary>  
        /// 生成16位的MD5散列值  
        /// </summary>  
        /// <param name="data">要算MD5的字符串</param>  
        /// <returns></returns>  
        public static string HashMD516(string data)
        {
            var md5 = new MD5CryptoServiceProvider();
            byte[] bytes = Encoding.UTF8.GetBytes(data);
            return ByteStrConvertHelper.ToString(md5.ComputeHash(bytes)).Substring(8, 16);
        }

        /// <summary>  
        /// 对字符串进行SHA1散列  
        /// </summary>  
        /// <param name="data">需要哈稀的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>密文</returns>  
        public static string HashSHA1(string data, bool isBase64 = false)
        {
            var StrRes = Encoding.UTF8.GetBytes(data);
            HashAlgorithm iSHA = new SHA1CryptoServiceProvider();
            StrRes = iSHA.ComputeHash(StrRes);
            if (isBase64)
                return Convert.ToBase64String(StrRes);
            else
                return ByteStrConvertHelper.ToString(StrRes);
        }

        /// <summary>  
        /// SHA256加密，不可逆转  
        /// </summary>  
        /// <param name="data">string data:被加密的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>返回加密后的字符串</returns>  
        public static string HashSHA256(string data, bool isBase64 = false)
        {
            SHA256 s256 = new SHA256CryptoServiceProvider();
            byte[] byte1 = Encoding.UTF8.GetBytes(data);
            byte1 = s256.ComputeHash(byte1);
            s256.Clear();
            if (isBase64)
                return Convert.ToBase64String(byte1);
            else
                return ByteStrConvertHelper.ToString(byte1);
        }

        /// <summary>  
        /// SHA384加密，不可逆转  
        /// </summary>  
        /// <param name="data">string data:被加密的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>返回加密后的字符串</returns>  
        public static string HashSHA384(string data, bool isBase64 = false)
        {
            SHA384 s384 = new SHA384CryptoServiceProvider();
            byte[] byte1 = Encoding.UTF8.GetBytes(data);
            byte1 = s384.ComputeHash(byte1);
            s384.Clear();
            if (isBase64)
                return Convert.ToBase64String(byte1);
            else
                return ByteStrConvertHelper.ToString(byte1);
        }

        /// <summary>  
        /// SHA512加密，不可逆转  
        /// </summary>  
        /// <param name="data">string data:被加密的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>返回加密后的字符串</returns>  
        public static string HashSHA512(string data, bool isBase64 = false)
        {
            SHA512 s512 = new SHA512CryptoServiceProvider();
            byte[] byte1 = Encoding.Default.GetBytes(data);
            byte1 = s512.ComputeHash(byte1);
            s512.Clear();
            if (isBase64)
                return Convert.ToBase64String(byte1);
            else
                return ByteStrConvertHelper.ToString(byte1);
        }
        #endregion

        #region 带混淆字符串的散列  
        /// <summary>  
        /// 对字符串进行HmacMD5散列  
        /// </summary>  
        /// <param name="key">密钥</param>  
        /// <param name="data">需要哈稀的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>密文</returns>  
        public static string HmacMD5(string key, string data, bool isBase64 = false)
        {
            var StrRes = Encoding.UTF8.GetBytes(data);
            var bkey = Encoding.UTF8.GetBytes(key);
            var hmacSha1 = new HMACMD5(bkey);
            StrRes = hmacSha1.ComputeHash(StrRes);
            if (isBase64)
                return Convert.ToBase64String(StrRes);
            else
                return ByteStrConvertHelper.ToString(StrRes);
        }

        /// <summary>  
        /// 对字符串进行HmacSHA1散列  
        /// </summary>  
        /// <param name="key">密钥</param>  
        /// <param name="data">需要哈稀的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>密文</returns>  
        public static string HmacSHA1(string key, string data, bool isBase64 = false)
        {
            var StrRes = Encoding.UTF8.GetBytes(data);
            var bkey = Encoding.UTF8.GetBytes(key);
            HMACSHA1 hmacSha1 = new HMACSHA1(bkey);
            StrRes = hmacSha1.ComputeHash(StrRes);
            if (isBase64)
                return Convert.ToBase64String(StrRes);
            else
                return ByteStrConvertHelper.ToString(StrRes);
        }

        /// <summary>  
        /// 对字符串进行HmacSHA256散列  
        /// </summary>  
        /// <param name="key">密钥</param>  
        /// <param name="data">需要哈稀的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>密文</returns>  
        public static string HmacSHA256(string key, string data, bool isBase64 = false)
        {
            var StrRes = Encoding.UTF8.GetBytes(data);
            var bkey = Encoding.UTF8.GetBytes(key);
            var hmacSha1 = new HMACSHA256(bkey);
            StrRes = hmacSha1.ComputeHash(StrRes);
            if (isBase64)
                return Convert.ToBase64String(StrRes);
            else
                return ByteStrConvertHelper.ToString(StrRes);
        }

        /// <summary>  
        /// 对字符串进行HmacSHA384散列  
        /// </summary>  
        /// <param name="key">密钥</param>  
        /// <param name="data">需要哈稀的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>密文</returns>  
        public static string HmacSHA384(string key, string data, bool isBase64 = false)
        {
            var StrRes = Encoding.UTF8.GetBytes(data);
            var bkey = Encoding.UTF8.GetBytes(key);
            var hmacSha1 = new HMACSHA384(bkey);
            StrRes = hmacSha1.ComputeHash(StrRes);
            if (isBase64)
                return Convert.ToBase64String(StrRes);
            else
                return ByteStrConvertHelper.ToString(StrRes);
        }

        /// <summary>  
        /// 对字符串进行HmacSHA512散列  
        /// </summary>  
        /// <param name="key">密钥</param>  
        /// <param name="data">需要哈稀的字符串</param>  
        /// <param name="isBase64">是否采用Base64</param>  
        /// <returns>密文</returns>  
        public static string HmacSHA512(string key, string data, bool isBase64 = false)
        {
            var StrRes = Encoding.UTF8.GetBytes(data);
            var bkey = Encoding.UTF8.GetBytes(key);
            var hmacSha1 = new HMACSHA512(bkey);
            StrRes = hmacSha1.ComputeHash(StrRes);
            if (isBase64)
                return Convert.ToBase64String(StrRes);
            else
                return ByteStrConvertHelper.ToString(StrRes);
        }
        #endregion

        #endregion

        #region 非对称加密算法  
        /// <summary>  
        /// RSA加密  
        /// </summary>  
        /// <param name="plaintData">明文</param>  
        /// <param name="publicKey">RSA公钥</param>  
        /// <param name="isBase64">输出数据是否用Base64编码</param>  
        /// <returns></returns>  
        public static string RSAEncrypt(string plaintData, string publicKey = DefaultRSAPublicKey, bool isBase64 = false)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            var cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintData), false);
            if (isBase64)
                return Convert.ToBase64String(cipherbytes);
            else
                return ByteStrConvertHelper.ToString(cipherbytes);
        }
        /// <summary>  
        /// RSA解密  
        /// </summary>  
        /// <param name="encryptData">密文</param>  
        /// <param name="privateKey">RSA私钥</param>  
        /// <param name="isBase64">密文数据是否用Base64编码</param>  
        /// <returns></returns>  
        public static string RSADecrypt(string encryptData, string privateKey = DefaultRSAPublicKey, bool isBase64 = false)
        {
            byte[] bData;
            if (isBase64)
                bData = Convert.FromBase64String(encryptData);
            else
                bData = ByteStrConvertHelper.ToBytes(encryptData);
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);
            var cipherbytes = rsa.Decrypt(bData, false);
            return Encoding.UTF8.GetString(cipherbytes);
        }
        /// <summary>  
        /// RSA加密  
        /// </summary>  
        /// <param name="plaintData">明文</param>  
        /// <param name="publicKey">RSA公钥</param>  
        /// <param name="isBase64">输出数据是否用Base64编码</param>  
        /// <returns></returns>  
        public static string RSAEncrypt(string plaintData, RSAParameters publicKey, bool isBase64 = false)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(publicKey);
            var cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintData), false);
            if (isBase64)
                return Convert.ToBase64String(cipherbytes);
            else
                return ByteStrConvertHelper.ToString(cipherbytes);
        }
        /// <summary>  
        /// RSA解密  
        /// </summary>  
        /// <param name="encryptData">密文</param>  
        /// <param name="privateKey">RSA私钥</param>  
        /// <param name="isBase64">密文数据是否用Base64编码</param>  
        /// <returns></returns>  
        public static string RSADecrypt(string encryptData, RSAParameters privateKey, bool isBase64 = false)
        {
            byte[] bData;
            if (isBase64)
                bData = Convert.FromBase64String(encryptData);
            else
                bData = ByteStrConvertHelper.ToBytes(encryptData);
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(privateKey);
            var cipherbytes = rsa.Decrypt(bData, false);
            return Encoding.UTF8.GetString(cipherbytes);
        }
        #endregion
    }

    /// <summary>  
    /// RSA加解密类  
    /// </summary>  
    public class RSACryptionHelper
    {
        #region RSA 加密解密   

        #region RSA 的密钥产生   
        /// <summary>  
        /// RSA 的密钥产生 产生私钥 和公钥   
        /// </summary>  
        /// <param name="xmlKeys"></param>  
        /// <param name="xmlPublicKey"></param>  
        public void RSAKey(out string xmlKeys, out string xmlPublicKey)
        {
            var rsa = new RSACryptoServiceProvider();
            xmlKeys = rsa.ToXmlString(true);
            xmlPublicKey = rsa.ToXmlString(false);
        }
        #endregion

        #region RSA的加密函数   
        //##############################################################################   
        //RSA 方式加密   
        //说明KEY必须是XML的行式,返回的是字符串   
        //在有一点需要说明！！该加密方式有 长度 限制的！！   
        //##############################################################################   

        //RSA的加密函数  string  
        /// <summary>  
        /// RSA加密  
        /// </summary>  
        /// <param name="xmlPublicKey"></param>  
        /// <param name="m_strEncryptString"></param>  
        /// <returns></returns>  
        public string RSAEncrypt(string xmlPublicKey, string m_strEncryptString)
        {

            byte[] PlainTextBArray;
            byte[] CypherTextBArray;
            string Result;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlPublicKey);
            PlainTextBArray = (new UnicodeEncoding()).GetBytes(m_strEncryptString);
            CypherTextBArray = rsa.Encrypt(PlainTextBArray, false);
            Result = Convert.ToBase64String(CypherTextBArray);
            return Result;

        }
        //RSA的加密函数 byte[]  
        /// <summary>  
        /// RSA解密  
        /// </summary>  
        /// <param name="xmlPublicKey"></param>  
        /// <param name="EncryptString"></param>  
        /// <returns></returns>  
        public string RSAEncrypt(string xmlPublicKey, byte[] EncryptString)
        {

            byte[] CypherTextBArray;
            string Result;
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlPublicKey);
            CypherTextBArray = rsa.Encrypt(EncryptString, false);
            Result = Convert.ToBase64String(CypherTextBArray);
            return Result;

        }
        #endregion

        #region RSA的解密函数   
        /// <summary>  
        /// RSA的解密函数  string  
        /// </summary>  
        /// <param name="xmlPrivateKey"></param>  
        /// <param name="m_strDecryptString"></param>  
        /// <returns></returns>  
        public string RSADecrypt(string xmlPrivateKey, string m_strDecryptString)
        {
            byte[] PlainTextBArray;
            byte[] DypherTextBArray;
            string Result;
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlPrivateKey);
            PlainTextBArray = Convert.FromBase64String(m_strDecryptString);
            DypherTextBArray = rsa.Decrypt(PlainTextBArray, false);
            Result = (new UnicodeEncoding()).GetString(DypherTextBArray);
            return Result;

        }

        /// <summary>  
        /// RSA的解密函数  byte  
        /// </summary>  
        /// <param name="xmlPrivateKey"></param>  
        /// <param name="DecryptString"></param>  
        /// <returns></returns>  
        public string RSADecrypt(string xmlPrivateKey, byte[] DecryptString)
        {
            byte[] DypherTextBArray;
            string Result;
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlPrivateKey);
            DypherTextBArray = rsa.Decrypt(DecryptString, false);
            Result = (new UnicodeEncoding()).GetString(DypherTextBArray);
            return Result;

        }
        #endregion

        #endregion

        #region RSA 数字签名   

        #region 获取Hash描述表  
        /// <summary>  
        /// 获取Hash描述表  
        /// </summary>  
        /// <param name="m_strSource"></param>  
        /// <param name="HashData"></param>  
        /// <returns></returns>  
        public bool GetHash(string m_strSource, ref byte[] HashData)
        {
            //从字符串中取得Hash描述   
            byte[] Buffer;
            var MD5 = HashAlgorithm.Create("MD5");
            Buffer = Encoding.UTF8.GetBytes(m_strSource);
            HashData = MD5.ComputeHash(Buffer);

            return true;
        }

        /// <summary>  
        /// 获取Hash描述表  
        /// </summary>  
        /// <param name="m_strSource"></param>  
        /// <param name="strHashData"></param>  
        /// <returns></returns>  
        public bool GetHash(string m_strSource, ref string strHashData)
        {
            //从字符串中取得Hash描述   
            byte[] Buffer;
            byte[] HashData;
            var MD5 = HashAlgorithm.Create("MD5");
            Buffer = Encoding.UTF8.GetBytes(m_strSource);
            HashData = MD5.ComputeHash(Buffer);

            strHashData = Convert.ToBase64String(HashData);
            return true;

        }

        /// <summary>  
        /// 获取Hash描述表  
        /// </summary>  
        /// <param name="objFile"></param>  
        /// <param name="HashData"></param>  
        /// <returns></returns>  
        public bool GetHash(FileStream objFile, ref byte[] HashData)
        {
            //从文件中取得Hash描述   
            var MD5 = HashAlgorithm.Create("MD5");
            HashData = MD5.ComputeHash(objFile);
            objFile.Close();

            return true;

        }

        /// <summary>  
        /// 获取Hash描述表  
        /// </summary>  
        /// <param name="objFile"></param>  
        /// <param name="strHashData"></param>  
        /// <returns></returns>  
        public bool GetHash(FileStream objFile, ref string strHashData)
        {
            //从文件中取得Hash描述   
            byte[] HashData;
            var MD5 = HashAlgorithm.Create("MD5");
            HashData = MD5.ComputeHash(objFile);
            objFile.Close();

            strHashData = Convert.ToBase64String(HashData);

            return true;
        }
        #endregion

        #region RSA 签名  
        /// <summary>  
        /// RSA 签名  
        /// </summary>  
        /// <param name="privateKey">Xml私钥</param>  
        /// <param name="hashData">待签名Hash描述</param>  
        /// <param name="signatureData">签名后的结果</param>  
        /// <returns></returns>  
        public bool Signature(string privateKey, byte[] hashData, ref byte[] signatureData)
        {
            try
            {
                var RSA = new RSACryptoServiceProvider();
                RSA.FromXmlString(privateKey);
                var RSAFormatter = new RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5   
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名   
                signatureData = RSAFormatter.CreateSignature(hashData);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>  
        /// RSA 签名  
        /// </summary>  
        /// <param name="privateKey">Xml私钥</param>  
        /// <param name="hashData">待签名Hash描述</param>  
        /// <param name="signatureData">签名后的结果</param>  
        /// <returns></returns>  
        public bool Signature(string privateKey, byte[] hashData, ref string signatureData)
        {
            try
            {
                var RSA = new RSACryptoServiceProvider();
                RSA.FromXmlString(privateKey);
                var RSAFormatter = new RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5   
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名   
                signatureData = Convert.ToBase64String(RSAFormatter.CreateSignature(hashData));
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>  
        /// RSA 签名  
        /// </summary>  
        /// <param name="privateKey">Xml私钥</param>  
        /// <param name="hashData">待签名Hash描述</param>  
        /// <param name="signatureData">签名后的结果</param>  
        /// <returns></returns>  
        public bool Signature(string privateKey, string hashData, ref byte[] signatureData)
        {
            try
            {
                var RSA = new RSACryptoServiceProvider();
                RSA.FromXmlString(privateKey);
                var RSAFormatter = new RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5   
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名   
                var bHashData = Convert.FromBase64String(hashData);
                signatureData = RSAFormatter.CreateSignature(bHashData);

                return true;
            }
            catch { return false; }
        }

        /// <summary>  
        /// RSA 签名  
        /// </summary>  
        /// <param name="privateKey">Xml私钥</param>  
        /// <param name="hashData">待签名Hash描述</param>  
        /// <param name="signatureData">签名后的结果</param>  
        /// <returns></returns>  
        public bool Signature(string privateKey, string hashData, ref string signatureData)
        {
            try
            {
                var RSA = new RSACryptoServiceProvider();
                RSA.FromXmlString(privateKey);
                var RSAFormatter = new RSAPKCS1SignatureFormatter(RSA);
                //设置签名的算法为MD5   
                RSAFormatter.SetHashAlgorithm("MD5");
                //执行签名   
                var bHashData = Convert.FromBase64String(hashData);
                signatureData = Convert.ToBase64String(RSAFormatter.CreateSignature(bHashData));
                return true;
            }
            catch { return false; }
        }
        #endregion

        #region RSA 签名验证   
        /// <summary>  
        /// RSA签名验证（验证时，函数RSADeformatter.VerifySignature先用公钥解密signatureData）  
        /// </summary>  
        /// <param name="publicKey">Xml字符串公钥</param>  
        /// <param name="hashData">Hash描述(刚生成的报文摘要)</param>  
        /// <param name="signatureData">签名后的结果(等待验证的私钥加密的Hash描述)</param>  
        /// <returns></returns>  
        public bool VerifySignature(string publicKey, byte[] hashData, byte[] signatureData)
        {
            var RSA = new RSACryptoServiceProvider();
            RSA.FromXmlString(publicKey);
            var RSADeformatter = new RSAPKCS1SignatureDeformatter(RSA);
            //指定解密的时候HASH算法为MD5   
            RSADeformatter.SetHashAlgorithm("MD5");
            return (RSADeformatter.VerifySignature(hashData, signatureData));
        }
        /// <summary>  
        /// RSA签名验证（验证时，函数RSADeformatter.VerifySignature先用公钥解密signatureData）  
        /// </summary>  
        /// <param name="publicKey">Xml字符串公钥</param>  
        /// <param name="hashData">Hash描述(刚生成的报文摘要)</param>  
        /// <param name="signatureData">签名后的结果(等待验证的私钥加密的Hash描述)</param>  
        /// <returns></returns>  
        public bool VerifySignature(string publicKey, string hashData, byte[] signatureData)
        {
            byte[] bHashData = Convert.FromBase64String(hashData);
            return VerifySignature(publicKey, bHashData, signatureData);
        }
        /// <summary>  
        /// RSA签名验证（验证时，函数RSADeformatter.VerifySignature先用公钥解密signatureData）  
        /// </summary>  
        /// <param name="publicKey">Xml字符串公钥</param>  
        /// <param name="hashData">Hash描述(刚生成的报文摘要)</param>  
        /// <param name="signatureData">签名后的结果(等待验证的私钥加密的Hash描述)</param>  
        /// <returns></returns>  
        public bool VerifySignature(string publicKey, byte[] hashData, string signatureData)
        {
            var bSignatureData = Convert.FromBase64String(signatureData);
            return VerifySignature(publicKey, hashData, bSignatureData);
        }
        /// <summary>  
        /// RSA签名验证（验证时，函数RSADeformatter.VerifySignature先用公钥解密signatureData）  
        /// </summary>  
        /// <param name="publicKey">Xml字符串公钥</param>  
        /// <param name="hashData">Hash描述(刚生成的报文摘要)</param>  
        /// <param name="signatureData">签名后的结果(等待验证的私钥加密的Hash描述)</param>  
        /// <returns></returns>  
        public bool VerifySignature(string publicKey, string hashData, string signatureData)
        {
            var bHashData = Convert.FromBase64String(hashData);
            var bSignatureData = Convert.FromBase64String(signatureData);
            return VerifySignature(publicKey, bHashData, bSignatureData);
        }
        #endregion

        #endregion
    }
}
