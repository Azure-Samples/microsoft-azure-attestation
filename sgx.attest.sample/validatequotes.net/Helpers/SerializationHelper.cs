using System;
using System.IO;
using System.Reflection;
using System.Text.Json;

namespace validatequotes
{
    public class SerializationHelper
    {
        public static T ReadFromFile<T>(string filePath)
        {
            T persistedObject = default;

            try
            {
                var deserializedObject = JsonSerializer.Deserialize<T>(File.ReadAllText(filePath));
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

        public static void WriteToFile<T>(string fileName, T persistedObject)
        {
            File.WriteAllText(fileName, JsonSerializer.Serialize(persistedObject));
        }
    }
}
