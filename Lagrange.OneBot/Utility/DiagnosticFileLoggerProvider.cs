using Microsoft.Extensions.Logging;

namespace Lagrange.OneBot.Utility;

public sealed class DiagnosticFileLoggerProvider : ILoggerProvider
{
    private readonly object _lock = new();

    private readonly string _logPath;

    public DiagnosticFileLoggerProvider(string logDirectory)
    {
        Directory.CreateDirectory(logDirectory);
        _logPath = Path.Combine(logDirectory, $"runtime-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.log");
    }

    public ILogger CreateLogger(string categoryName) => new DiagnosticFileLogger(categoryName, _logPath, _lock);

    public void Dispose()
    {
    }

    private sealed class DiagnosticFileLogger : ILogger
    {
        private readonly string _categoryName;

        private readonly string _logPath;

        private readonly object _lock;

        public DiagnosticFileLogger(string categoryName, string logPath, object @lock)
        {
            _categoryName = categoryName;
            _logPath = logPath;
            _lock = @lock;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;

            string line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [{logLevel}] [{_categoryName}] {formatter(state, exception)}";
            if (exception != null) line += Environment.NewLine + exception;

            lock (_lock)
            {
                File.AppendAllText(_logPath, line + Environment.NewLine);
            }
        }
    }
}
