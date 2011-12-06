require_relative 'oauth'
require 'test/unit'

class TestToken < MiniTest::Unit::TestCase
        def test_new_token
                key = '8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc'
                secret = 'x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA'
                t = OAUTH::Token.new(key, secret)
                assert_equal(t.to_s, 'oauth_token=8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc&oauth_token_secret=x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA')
        end
        
        def test_token_from_string
                t = OAUTH::Token.from_string('oauth_token=8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc&oauth_token_secret=x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA&oauth_callback_confirmed=true')
                assert_equal(t.token, '8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc')
                assert_equal(t.token_secret, 'x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA')
                assert_equal(t.callback_confirmed, 'true')
        end
end

class TestConsumer < MiniTest::Unit::TestCase
        def test_new_consumer
                key = 'GDdmIQH6jhtmLUypg82g'
                secret = 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98'
                c = OAUTH::Consumer.new(key, secret)
                assert_equal('', '')
                assert_raises(RuntimeError) { OAUTH::Consumer.new(nil, nil) }
        end
end

class TestRequest < MiniTest::Unit::TestCase
        def test_new_request
                c = OAUTH::Consumer.new('GDdmIQH6jhtmLUypg82g', 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98')
                t = OAUTH::Token.new('8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc', 'x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA')
                r = OAUTH::Request.from_consumer_and_token(c, nil, 'POST', url='http://api.twitter.com/oauth/request_token', callback_url="http://localhost:3005/the_dance/process_callback?service_provider_id=11")
                # assert_equal(r.normalized_params, 'oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A3005%252Fthe_dance%252Fprocess_callback%253Fservice_provider_id%253D11%26oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DQP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272323042%26oauth_version%3D1.0')
                # puts r.sign(OAUTH::SignatureMethod::HMAC_SHA1.new, c)
        end
end