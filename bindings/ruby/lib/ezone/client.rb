require 'net/http'
require 'json'
require 'uri'

module Ezone
  class Error < StandardError
    attr_reader :status, :body

    def initialize(status, message, body = nil)
      super(message)
      @status = status
      @body   = body
    end
  end

  class Client
    def initialize(base_url:, timeout: 10)
      @base_url = base_url.chomp('/')
      @timeout  = timeout
    end

    # ── Registration ──────────────────────────────────────────────────────────

    def begin_registration(email:)
      post('/v1/auth/register/begin', { email: email })
    end

    def complete_registration(magic_token:, device_public_key:, device_name:)
      post('/v1/auth/register/complete', {
        magic_token:       magic_token,
        device_public_key: device_public_key,
        device_name:       device_name,
      })
    end

    # ── Login ─────────────────────────────────────────────────────────────────

    def begin_login(email:)
      post('/v1/auth/login/begin', { email: email })
    end

    def complete_login(email:, challenge:, signature:, device_public_key:)
      post('/v1/auth/login/complete', {
        email:             email,
        challenge:         challenge,
        signature:         signature,
        device_public_key: device_public_key,
      })
    end

    # ── Session ───────────────────────────────────────────────────────────────

    def verify_session(token)
      get('/v1/auth/session', token)
    end

    def refresh_session(token)
      post('/v1/auth/session/refresh', {}, token)
    end

    def logout(token)
      post('/v1/auth/session/logout', {}, token)
      nil
    end

    # ── Reset ─────────────────────────────────────────────────────────────────

    def begin_reset(email:)
      post('/v1/auth/reset/begin', { email: email })
    end

    def complete_reset(magic_token:, device_public_key:, device_name:)
      post('/v1/auth/reset/complete', {
        magic_token:       magic_token,
        device_public_key: device_public_key,
        device_name:       device_name,
      })
    end

    # ── Recovery ──────────────────────────────────────────────────────────────

    def generate_recovery_codes(token)
      post('/v1/auth/recovery/generate', {}, token)
    end

    def recover_with_code(email:, code:, device_public_key:, device_name:)
      post('/v1/auth/recovery/use', {
        email:             email,
        code:              code,
        device_public_key: device_public_key,
        device_name:       device_name,
      })
    end

    # ── Devices ───────────────────────────────────────────────────────────────

    def list_devices(token)
      get('/v1/auth/devices', token)
    end

    def begin_add_device(token)
      post('/v1/auth/devices/add/begin', {}, token)
    end

    def complete_add_device(magic_token:, device_public_key:, device_name:)
      post('/v1/auth/devices/add/complete', {
        magic_token:       magic_token,
        device_public_key: device_public_key,
        device_name:       device_name,
      })
    end

    def revoke_device(token, device_id)
      request(:delete, "/v1/auth/devices/#{device_id}", nil, token)
      nil
    end

    private

    def post(path, body, token = nil)
      request(:post, path, body, token)
    end

    def get(path, token)
      request(:get, path, nil, token)
    end

    def request(method, path, body, token)
      uri  = URI.parse(@base_url + path)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = @timeout
      http.read_timeout = @timeout

      req = case method
            when :post   then Net::HTTP::Post.new(uri.request_uri)
            when :get    then Net::HTTP::Get.new(uri.request_uri)
            when :delete then Net::HTTP::Delete.new(uri.request_uri)
            end

      req['Content-Type'] = 'application/json'
      req['Accept']       = 'application/json'
      req['Authorization'] = "Bearer #{token}" if token
      req.body = body.to_json if body

      resp = http.request(req)
      parsed = JSON.parse(resp.body, symbolize_names: true)

      unless resp.is_a?(Net::HTTPSuccess)
        raise Error.new(resp.code.to_i, parsed[:error] || 'error', parsed)
      end

      parsed
    end
  end
end
