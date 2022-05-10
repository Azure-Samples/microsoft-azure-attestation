using System;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace validatequotes
{
    public class SerializationHelper
    {
        public async static Task<T> ReadFromFileAsync<T>(string filePath)
        {
            T persistedObject = default;

            try
            {
                var deserializedObject = await JsonSerializer.DeserializeAsync<T>(new FileStream(filePath, FileMode.Open));
                if (deserializedObject != null)
                {
                    persistedObject = deserializedObject;
                }
            }
            catch (Exception)
            {
                // Ignore on purpose and return default object value
            }

            return persistedObject;
        }

        public async static Task WriteToFileAsync<T>(string fileName, T persistedObject)
        {
            await File.WriteAllTextAsync(fileName, JsonSerializer.Serialize(persistedObject));
        }
    }
}
