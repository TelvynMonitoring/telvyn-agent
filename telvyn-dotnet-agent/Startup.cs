using System.Diagnostics;
using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Trace;

[assembly: HostingStartup(typeof(Telvyn.Agent.Startup))]

namespace Telvyn.Agent;

public sealed class Startup : IHostingStartup
{
    public void Configure(IWebHostBuilder builder)
    {
        if (string.Equals(Environment.GetEnvironmentVariable("OTEL_SDK_DISABLED"), "true", StringComparison.OrdinalIgnoreCase)) return;
        builder.ConfigureServices(services => {
            services.AddHostedService<HandledErrors>();
            services.AddOpenTelemetry().WithTracing(tracing => tracing
            .AddAspNetCoreInstrumentation(options => options.RecordException = true)
            .AddProcessor(new CompletionLogs()).AddOtlpExporter(options => {
                options.Protocol = OtlpExportProtocol.HttpProtobuf;
                if (Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT") == null && Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == null)
                    options.Endpoint = new Uri("http://localhost:4318");
            }));
        });
    }
}

sealed class HandledErrors : IHostedService, IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>
{
    IDisposable? listeners;
    readonly ConcurrentBag<IDisposable> subscriptions = new();
    public Task StartAsync(CancellationToken token) { listeners = DiagnosticListener.AllListeners.Subscribe(this); return Task.CompletedTask; }
    public Task StopAsync(CancellationToken token) { listeners?.Dispose(); while (subscriptions.TryTake(out var subscription)) subscription.Dispose(); return Task.CompletedTask; }
    public void OnNext(DiagnosticListener listener)
    {
        if (listener.Name == "Microsoft.AspNetCore") subscriptions.Add(listener.Subscribe(this, name => name == "Microsoft.AspNetCore.Diagnostics.HandledException"));
    }
    public void OnNext(KeyValuePair<string, object?> diagnostic)
    {
        if (diagnostic.Value?.GetType().GetProperty("exception")?.GetValue(diagnostic.Value) is Exception error)
            Activity.Current?.AddEvent(new ActivityEvent("exception", tags: new ActivityTagsCollection {
                ["exception.type"] = error.GetType().FullName, ["exception.message"] = error.Message, ["exception.stacktrace"] = error.ToString()
            }));
    }
    public void OnCompleted() { }
    public void OnError(Exception error) { }
}

sealed class CompletionLogs : BaseProcessor<Activity>
{
    public override void OnEnd(Activity activity)
    {
        activity.SetTag("telvyn.sdk.name", "telvyn-dotnet-agent");
        activity.SetTag("telvyn.sdk.version", "0.1.0");
        activity.SetTag("process.runtime.version", Environment.Version.ToString());
        foreach (var key in new[] { "http.url", "http.target", "url.full" })
            if (activity.GetTagItem(key) is string url) activity.SetTag(key, url.Split('?')[0]);
        activity.SetTag("url.query", null);
        if (activity.Kind != ActivityKind.Server || activity.TraceId == default || activity.SpanId == default) return;
        var rawStatus = activity.GetTagItem("http.response.status_code") ?? activity.GetTagItem("http.status_code");
        int? status = int.TryParse(rawStatus?.ToString(), out var parsed) ? parsed : null;
        Console.WriteLine(JsonSerializer.Serialize(new {
            service = Environment.GetEnvironmentVariable("OTEL_SERVICE_NAME"), level = status >= 500 ? "error" : "info",
            message = "HTTP request completed", method = activity.GetTagItem("http.request.method") ?? activity.GetTagItem("http.method"),
            status, trace_id = activity.TraceId.ToString(), span_id = activity.SpanId.ToString()
        }));
    }
}
