using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Text;

namespace NugetLibs.NetHelpTool
{
    /// <summary>
    /// DataTable数据类型转换帮助类
    /// </summary>
    public static class DataTableHelper
    {
        /// <summary>
        /// 把具体对象集合转成DataTable的数据
        /// </summary>
        /// <typeparam name="T">集合的元素类型</typeparam>
        /// <param name="collection">具体对象集合</param>
        /// <returns>DataTable的数据</returns>
        public static DataTable ToDataTable<T>(IEnumerable<T> collection)
        {
            var props = typeof(T).GetProperties();
            var dt = new DataTable();
            dt.Columns.AddRange(props.Select(p => new DataColumn(p.Name, p.PropertyType)).ToArray());
            if (collection.Count() > 0)
            {
                for (int i = 0; i < collection.Count(); i++)
                {
                    ArrayList tempList = new ArrayList();
                    foreach (PropertyInfo pi in props)
                    {
                        object obj = pi.GetValue(collection.ElementAt(i), null);
                        tempList.Add(obj);
                    }
                    object[] array = tempList.ToArray();
                    dt.LoadDataRow(array, true);
                }
            }
            return dt;
        }

        /// <summary>
        /// 把DataTable的数据转换成具体集合对象
        /// </summary>
        /// <typeparam name="T">集合的元素类型</typeparam>
        /// <param name="dt">DataTable的数据</param>
        /// <returns>具体集合对象</returns>
        public static IList<T> ConvertToModel<T>(DataTable dt) where T : new()
        {
            // 定义集合
            IList<T> ts = new List<T>();
            // 获得此模型的类型   
            Type type = typeof(T);
            string tempName = "";
            foreach (DataRow dr in dt.Rows)
            {
                T t = new T();
                // 获得此模型的公共属性   
                PropertyInfo[] propertys = t.GetType().GetProperties();
                foreach (PropertyInfo pi in propertys)
                {
                    tempName = pi.Name;  // 检查DataTable是否包含此列  
                    if (dt.Columns.Contains(tempName))
                    {
                        // 判断此属性是否有Setter   
                        if (!pi.CanWrite) continue;
                        object value = dr[tempName];
                        if (value != DBNull.Value)
                            pi.SetValue(t, value, null);
                    }
                }
                ts.Add(t);
            }
            return ts;
        }
    }
}
