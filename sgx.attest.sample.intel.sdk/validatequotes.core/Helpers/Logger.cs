using Newtonsoft.Json.Linq;
using System;

namespace validatequotes
{
    public class Logger
    {
        public static void WriteLine(string message)
        {
            var messageLines = message.Split('\n');
            foreach (var line in messageLines)
            {
                var theTime = DateTime.Now.TimeOfDay.ToString(@"hh\:mm\:ss\.fff");
                Console.WriteLine($"[{theTime}] : {line}");
            }
        }
        public static void WriteLine(int tabIndent, int maxCharsPerLine, string firstIndentString, string message)
        {
            string padding = firstIndentString.Substring(0, Math.Min(tabIndent, firstIndentString.Length)).PadRight(tabIndent);

            for (int i = 0; i < message.Length; i += maxCharsPerLine)
            {
                var line = padding + message.Substring(i, Math.Min(maxCharsPerLine, message.Length - i));
                WriteLine(line);
                padding = "".PadLeft(tabIndent);
            }
        }

        public static void WriteBanner(string banner)
        {
            string separatorLine = new string('*', 120);
            WriteLine("");
            WriteLine(separatorLine);
            WriteLine($"*      {banner}");
            WriteLine(separatorLine);
            WriteLine("");
        }
    }
}
