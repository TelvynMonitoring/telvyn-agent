Gem::Specification.new do |spec|
  spec.name = 'telvyn-ruby-agent'
  spec.version = '0.1.0'
  spec.summary = 'Telvyn HTTP instrumentation for Rack applications'
  spec.authors = ['Telvyn']
  spec.files = ['lib/telvyn/auto.rb', 'README.md']
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 3.1'
  spec.add_dependency 'rack', '>= 3.0', '< 4'
  spec.add_dependency 'opentelemetry-sdk', '1.13.1'
  spec.add_dependency 'opentelemetry-exporter-otlp', '0.37.0'
  spec.add_dependency 'opentelemetry-instrumentation-rack', '0.31.2'
end
