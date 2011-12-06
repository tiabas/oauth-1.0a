require 'uri'
require 'openssl'
require 'base64'

module OAUTH
    OAUTH_CONSUMER_KEY = "GDdmIQH6jhtmLUypg82g"
    OAUTH_CONSUMER_SECRET = "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98"
    OAUTH_SIGNATURE_METHOD = "HMAC-SHA1"
    OAUTH_CALLBACK = "http://localhost:3005/the_dance/process_callback?service_provider_id=11"
    OAUTH_VERSION = 1.0

    def generate_verifier(length=8)
        # Generate pseudorandom number
        return 'pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY' || (0...length).map { |x| Random.rand(9) }.join
    end

    class Token
        attr_reader :callback_confirmed
        attr_accessor :token, :token_secret, :callback_url, :verifier

        def callback
            @callback
        end

        def callback=(callback_val)
            @callback = callback_val
            if not @callback.nil?
                @callback_confirmed = true
            end
        end

        def verifier=(verifier_val)
            @verifier = verifier_val
            if @verifier.nil?
                @verifier = generate_verifier
            end
        end
      
        def initialize(token, token_secret, callback_confirmed=nil)
           if token.nil? || token_secret.nil?
               fail "Token key and secret must be provided"
            end
            @token = token
            @token_secret = token_secret
            @callback_confirmed = callback_confirmed 
        end 
    
        def self.from_string(token_string)
            data = Hash.new(nil)
            params = token_string.split("&")
            params.each do |param|
                key, value = param.split("=")
                data[key.to_sym] = value
            end
            Token.new(data[:oauth_token], data[:oauth_token_secret], data[:oauth_callback_confirmed])
        end
    
        def to_s
            data = { 
                    oauth_token: @token,
                    oauth_token_secret: @token_secret
                    }
            if not @callback_confirmed.nil?
                data[:oauth_callback_confirmed] = true
            end
            URI.encode_www_form(data)
        end
    end 

    class Consumer 
        attr_accessor :key, :secret

        def initialize(consumer_key, consumer_secret)
           if consumer_key.nil? || consumer_secret.nil?
               fail "Consumer key and secret must be provided"
           end
           @key = consumer_key
           @secret= consumer_secret
        end

        def to_s
            URI.encode_www_form({oauth_consumer_key: @key, oauth_consumer_secret: @secret})
        end
    end

    class Request
        attr_reader :normalized_url, :nonce, :timestamp
        attr_accessor :token, :consumer, :base_uri, :http_method, :version, :params

        @@version=OAUTH_VERSION

        def self.generate_timestamp
            return 1272323042 || Time.now.to_i
        end

        def self.generate_nonce(length=8)
            #Generate pseudorandom number, hard-coded for now
            'QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk' || (0...length).map { |x| Random.rand(9) }.join
        end
    
        def self.from_consumer_and_token(consumer, token, method=HTTP_METHOD, url=nil, callback_url=nil, url_params=nil)
            default_params = {
                oauth_consumer_key: consumer.key,
                oauth_nonce: generate_nonce,
                oauth_timestamp: generate_timestamp,
                oauth_version: @@version
            }
            params =  url_params || Hash.new(nil) 
            params.merge!(default_params)
            if callback_url
                params[:oauth_callback] = callback_url
            end
            if token
                params[:oauth_token] = token.token
                if token.verifier
                    params[:oauth_verifier] = token.verifier
                end
            end
            Request.new(method, url, params)
        end
    
        def initialize(http_method, base_uri, params)
            @http_method = http_method.upcase
            @base_uri = base_uri
            @params = params || Hash.new(nil)      
        end
    
        def http_method=(method)
            @http_method = method.upcase
        end
    
        def base_uri=(value)
            @base_uri = value
            normalize_url(@base_uri)
        end
    
        def normalized_url
            if @normalized_url.nil?
               @normalize_url = normalize_url(@base_uri) 
            end
            @normalize_url
        end
        # normalize uri
        def normalize_url(url)
            if not url.nil?
                scheme, userinfo, host, port, registry, path, opaque, query, fragment = URI.split(url)
                if not ['https', 'http'].include? scheme
                    raise
                end
                @normalized_url = URI::Generic.new(scheme, userinfo, host, port,registry, path, opaque, query, fragment).to_s
            end
            url
        end
     
        def normalized_params
            sorted_params = @params.sort_by {|k, v| k }
            encoded_params = sorted_params.collect do |param_pair| 
                param_pair.map {|component| URI.encode_www_form_component(component) }.join("%3D")
            end
            param_string = encoded_params.join("%26")
        end
    
        def sign(signature_method, consumer, token=nil)
            if @params[:oauth_consumer_key].nil?
                @params[:oauth_consumer_key] = consumer.key
            end
        
            if token and @params[:oauth_token].nil?
                @params[:oauth_consumer_key]  = token.key
            end
            if signature_method
                puts signature_method.name
                @params[:oauth_signature_method] = signature_method.name
                @params[:oauth_signature] = signature_method.sign(self, consumer, token)
            end
        end
    end 
    

    module SignatureMethod
        class HMAC_SHA1 
            def name 
                'HMAC-SHA1'
            end
        
            def signing_base(request, consumer, token=nil)
                if request.normalized_url.nil?
                    raise
                end
                signature_components = [URI.encode_www_form_component(request.http_method), URI.encode_www_form_component(request.normalized_url), request.normalized_params]
                base_string = signature_components.join("&")
                puts base_string
                sigining_key = "#{consumer.key}&"
                if not token.nil?
                    sigining_key << token.key
                end
                return sigining_key, base_string
            end
    
            def sign(request, consumer, token=nil)
                key, raw = self.signing_base(request, consumer, token=nil)
                hash = OpenSSL::HMAC.digest('sha1',key, raw)
                Base64.encode64(hash).gsub(/\n/, '')
            end 
        end         
    end 
end