require 'rubygems'

# Preserve the application's gem paths; the operator supplies a matching Ruby ABI.
Gem.use_paths(Gem.dir, [__dir__, *Gem.path])
require 'telvyn/auto'

module Telvyn
  module InjectedBuilder
    def to_app
      app = super
      return app if !Telvyn.enabled? || app.is_a?(Telvyn::Middleware)
      Telvyn::Middleware.new(app)
    end
  end
end

Rack::Builder.prepend(Telvyn::InjectedBuilder)
