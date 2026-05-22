Gem::Specification.new do |s|
  s.name        = 'ezone-sdk'
  s.version     = '0.1.0'
  s.summary     = 'ezone passwordless authentication SDK'
  s.description = 'Ruby client for the ezone passwordless authentication REST API'
  s.license     = 'MIT'
  s.authors     = ['ezone contributors']
  s.homepage    = 'https://github.com/ezone-sdk/ezone-sdk'

  s.required_ruby_version = '>= 3.1.0'
  s.files = Dir['lib/**/*.rb']

  s.add_development_dependency 'rspec',   '~> 3.13'
  s.add_development_dependency 'webmock', '~> 3.23'
end
