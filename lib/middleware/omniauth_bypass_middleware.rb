# frozen_string_literal: true

require "csrf_token_verifier"

# omniauth loves spending lots cycles in its magic middleware stack
# this middleware bypasses omniauth middleware and only hits it when needed
class Middleware::OmniauthBypassMiddleware
  class AuthenticatorDisabled < StandardError; end

  def initialize(app, options = {})
    @app = app

    Discourse.plugins.each(&:notify_before_auth)

    # if you need to test this and are having ssl issues see:
    #  http://stackoverflow.com/questions/6756460/openssl-error-using-omniauth-specified-ssl-path-but-didnt-work
    # OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE if Rails.env.development?
    @omniauth = OmniAuth::Builder.new(app) do
      options(allowed_paths: '/auth')
      Discourse.authenticators.each do |authenticator|
        authenticator.register_middleware(self)
      end
    end

    @omniauth.before_request_phase do |env|
      # Check whether the authenticator is enabled
      if !Discourse.enabled_authenticators.any? { |a| a.name.to_sym == env['omniauth.strategy'].name.to_sym }
        raise AuthenticatorDisabled
      end

      # If the user is trying to reconnect to an existing account, store in session
      request.session[:auth_reconnect] = !!request.params["reconnect"]
    end

    OmniAuth.config.request_validation_phase = CSRFTokenVerifier.new

    only_one_provider = !SiteSetting.enable_local_logins && Discourse.enabled_authenticators.length == 1
    OmniAuth.config.allowed_request_methods = only_one_provider ? [:get, :post] : [:post]

    OmniAuth.config.on_failure do |env|
      if env['omniauth.error'] == AuthenticatorDisabled
        #  Authenticator is disabled, pretend it doesn't exist and pass request to app
        @app.call(env)
      else
        OmniAuth::FailureEndpoint.call(env)
      end
    end
  end

  def call(env)
    @omniauth.call(env)
  end

end
