---
id: ruby
title: Ruby
---

# Ruby SDK

Net::HTTP-based client with zero runtime dependencies. Supports Ruby 3.1+ and Rails.

## Installation

```bash
gem install ezone-sdk
```

Or in your `Gemfile`:

```ruby
gem 'ezone-sdk', '~> 0.1'
```

## Quick start

```ruby
require 'ezone'

client = Ezone::Client.new(base_url: 'https://auth.yourapp.com')

# Registration
result = client.begin_registration(email: 'alice@example.com')
puts result[:magic_token]

# Login
ch = client.begin_login(email: 'alice@example.com')
# sign ch[:challenge] with device key...

session = client.complete_login(
  email: 'alice@example.com',
  challenge: ch[:challenge],
  signature: '<base64url sig>',
  device_public_key: '<base64url SPKI DER>'
)
puts session[:token]
```

## Rails integration

```ruby
# config/initializers/ezone.rb
EZONE = Ezone::Client.new(base_url: ENV.fetch('EZONE_URL'))

# app/controllers/concerns/ezone_authentication.rb
module EzoneAuthentication
  extend ActiveSupport::Concern

  included do
    before_action :require_auth
  end

  private

  def require_auth
    token = request.headers['Authorization']&.delete_prefix('Bearer ')
    render json: { error: 'Unauthorized' }, status: :unauthorized and return unless token

    begin
      @current_user = EZONE.verify_session(token)
    rescue Ezone::Error
      render json: { error: 'Invalid token' }, status: :unauthorized
    end
  end
end

# app/controllers/api/v1/profile_controller.rb
class Api::V1::ProfileController < ApplicationController
  include EzoneAuthentication

  def show
    render json: { user_id: @current_user[:user_id] }
  end
end
```

## Full API

```ruby
module Ezone
  class Client
    def initialize(base_url:, timeout: 10)

    def begin_registration(email:)
    def complete_registration(magic_token:, device_public_key:, device_name:)

    def begin_login(email:)
    def complete_login(email:, challenge:, signature:, device_public_key:)

    def verify_session(token)
    def refresh_session(token)
    def logout(token)

    def begin_reset(email:)
    def complete_reset(magic_token:, device_public_key:, device_name:)

    def generate_recovery_codes(token)
    def recover_with_code(email:, code:, device_public_key:, device_name:)

    def list_devices(token)
    def begin_add_device(token)
    def complete_add_device(magic_token:, device_public_key:, device_name:)
    def revoke_device(token, device_id)
  end

  class Error < StandardError
    attr_reader :status, :body
  end
end
```
