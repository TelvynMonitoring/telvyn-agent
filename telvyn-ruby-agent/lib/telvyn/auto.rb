require 'rack'
require 'rack/body_proxy'
require 'json'
require 'opentelemetry/sdk'
require 'opentelemetry-exporter-otlp'
require 'opentelemetry/instrumentation/rack'

module Telvyn
  def self.enabled?
    ENV.fetch('OTEL_SDK_DISABLED', '').downcase != 'true'
  end

  class QuerySafeExporter < OpenTelemetry::Exporter::OTLP::Exporter
    def export(spans, timeout: nil)
      clean = spans.map do |original|
        span = original.dup
        attributes = original.attributes.dup
        attributes['telvyn.sdk.name'] = 'telvyn-ruby-agent'
        attributes['telvyn.sdk.version'] = '0.1.0'
        attributes['process.runtime.version'] = RUBY_VERSION
        %w[http.url http.target url.full].each do |key|
          attributes[key] = attributes[key].split('?', 2).first if attributes[key].is_a?(String)
        end
        attributes.delete('url.query')
        # SpanData tracks attributes before SDK limits. Preserve its dropped count
        # when the exporter adds identity or removes a query attribute.
        span.total_recorded_attributes += attributes.size - original.attributes.size
        span.attributes = attributes
        span
      end
      super(clean, timeout: timeout)
    end
  end

  class CompletionLogs
    def initialize(app)
      @app = app
    end

    def call(env)
      status, headers, body = @app.call(env)
      span = OpenTelemetry::Trace.current_span
      span.record_exception(env['sinatra.error']) if env['sinatra.error'].is_a?(Exception)
      if env['sinatra.route'].is_a?(String)
        span.name = env['sinatra.route']
        span.set_attribute('http.route', env['sinatra.route'].split(' ', 2).last)
      end
      context = span.context
      body = ::Rack::BodyProxy.new(body) do
        if context.valid?
          puts JSON.generate(service: ENV['OTEL_SERVICE_NAME'], level: status >= 500 ? 'error' : 'info',
            message: 'HTTP request completed', method: env['REQUEST_METHOD'], status: status,
            trace_id: context.hex_trace_id, span_id: context.hex_span_id)
          $stdout.flush
        end
      end
      [status, headers, body]
    end
  end

  class Middleware
    def initialize(app)
      @original_app = app
      @app = app
      if Telvyn.enabled?
        klass, *args = OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.middleware_args
        @app = klass.new(CompletionLogs.new(app), *args)
      end
    end

    def call(env)
      return @original_app.call(env) if env['telvyn.instrumented']
      env['telvyn.instrumented'] = true
      begin
        @app.call(env)
      ensure
        env.delete('telvyn.instrumented')
      end
    end
  end
end

if Telvyn.enabled?
  OpenTelemetry::SDK.configure do |config|
    config.add_span_processor(OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(Telvyn::QuerySafeExporter.new))
    config.use 'OpenTelemetry::Instrumentation::Rack'
  end
end
