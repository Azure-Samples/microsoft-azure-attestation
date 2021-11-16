namespace maa.signing.tool.utils
{
    public enum TracingLevel
    {
        Verbose = 0,
        Info,
        Warning,
        Error
    }

    public class Tracer
    {
        public static TracingLevel CurrentTracingLevel { get; set; } = TracingLevel.Info;

        public static void TraceVerbose(string message) { Trace(TracingLevel.Verbose, message); }
        public static void TraceInfo(string message) { Trace(TracingLevel.Info, message); }
        public static void TraceWarning(string message) { Trace(TracingLevel.Warning, message); }
        public static void TraceError(string message) { Trace(TracingLevel.Error, message); }
        public static void TraceRaw(string message) { TraceImpl(message); }

        private static void Trace(TracingLevel tracingLevel, string message)
        {
            if (tracingLevel >= CurrentTracingLevel)
            {
                TraceImpl(string.Format("{0}: {1}", tracingLevel.ToString(), message));
            }
        }

        private static void TraceImpl(string message)
        {
            Console.WriteLine(message);
        }
    }
}
