<?php
namespace Telvyn\Agent;

use OpenTelemetry\API\Trace\Propagation\TraceContextPropagator;
use OpenTelemetry\API\Trace\SpanInterface;
use OpenTelemetry\API\Trace\SpanKind;
use OpenTelemetry\API\Trace\StatusCode;
use OpenTelemetry\Contrib\Otlp\SpanExporter;
use OpenTelemetry\SDK\Common\Export\Http\PsrTransportFactory;
use OpenTelemetry\SDK\Resource\ResourceInfoFactory;
use OpenTelemetry\SDK\Sdk;
use OpenTelemetry\SDK\Trace\SpanProcessor\SimpleSpanProcessor;
use OpenTelemetry\SDK\Trace\TracerProvider;

final class HttpAgent
{
    private static ?SpanInterface $span = null;

    public static function boot(): void
    {
        if (strtolower(getenv('OTEL_SDK_DISABLED') ?: '') === 'true' || !isset($_SERVER['REQUEST_METHOD']) || self::$span !== null) return;
        $endpoint = getenv('OTEL_EXPORTER_OTLP_TRACES_ENDPOINT') ?: rtrim(getenv('OTEL_EXPORTER_OTLP_ENDPOINT') ?: 'http://localhost:4318', '/') . '/v1/traces';
        $transport = (new PsrTransportFactory())->create($endpoint, 'application/x-protobuf', timeout: 2, maxRetries: 0);
        $provider = TracerProvider::builder()->setResource(ResourceInfoFactory::defaultResource())
            ->addSpanProcessor(new SimpleSpanProcessor(new SpanExporter($transport)))->build();
        Sdk::builder()->setTracerProvider($provider)->setPropagator(TraceContextPropagator::getInstance())->setAutoShutdown(false)->buildAndRegisterGlobal();
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
        $carrier = array_filter(['traceparent'=>$_SERVER['HTTP_TRACEPARENT'] ?? null, 'tracestate'=>$_SERVER['HTTP_TRACESTATE'] ?? null]);
        $span = $provider->getTracer('telvyn.php-agent', '0.1.0')->spanBuilder($method . (is_string($path) ? ' ' . $path : ''))
            ->setParent(TraceContextPropagator::getInstance()->extract($carrier))->setSpanKind(SpanKind::KIND_SERVER)
            ->setAttribute('http.request.method', $method)
            ->setAttribute('telvyn.sdk.name', 'telvyn-php-agent')
            ->setAttribute('telvyn.sdk.version', '0.1.0')
            ->setAttribute('process.runtime.version', PHP_VERSION)->startSpan();
        if (is_string($path)) $span->setAttribute('url.path', $path);
        $scope = $span->activate();
        self::$span = $span;
        register_shutdown_function(static function () use ($provider, $span, $scope, $method): void {
            // PHP's HTTP SAPI sends 200 when no explicit response code was assigned.
            $status = http_response_code();
            if ($status === false) $status = 200;
            $span->setAttribute('http.response.status_code', $status);
            if ($status >= 500) $span->setStatus(StatusCode::STATUS_ERROR);
            $context = $span->getContext();
            if ($context->isValid()) file_put_contents('php://stderr', json_encode([
                'service'=>getenv('OTEL_SERVICE_NAME'), 'level'=>$status >= 500 ? 'error' : 'info',
                'message'=>'HTTP request completed', 'method'=>$method, 'status'=>$status,
                'trace_id'=>$context->getTraceId(), 'span_id'=>$context->getSpanId()
            ]) . "\n");
            $scope->detach();
            $span->end();
            $provider->shutdown();
        });
    }

    public static function recordException(\Throwable $error): void
    {
        self::$span?->recordException($error);
    }
}
