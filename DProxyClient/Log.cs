using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace DProxyClient
{
    public class Log
    {
        public static ILoggerFactory Factory = LoggerFactory.Create(builder => builder.AddDebug()
            .AddFilter("DProxyClient", LogLevel.Debug)
            .AddSimpleConsole(options =>
            {
                options.IncludeScopes = true;
                options.SingleLine = true;
                options.ColorBehavior = LoggerColorBehavior.Enabled;
                options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss.fff] ";
                options.UseUtcTimestamp = true;
            })
        );
    }
}
