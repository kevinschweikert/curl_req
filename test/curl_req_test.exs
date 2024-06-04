defmodule CurlReqTest do
  use ExUnit.Case, async: true
  doctest CurlReq
  import CurlReq

  @req_version :application.get_key(:req, :vsn) |> elem(1)

  defp default_header(), do: "-H \"accept-encoding: gzip\" -H \"user-agent: req/#{@req_version}\""

  describe "to_curl" do
    test "works with base URL" do
      assert "curl #{default_header()} -X GET https://catfact.ninja/fact" ==
               Req.new(url: "/fact", base_url: "https://catfact.ninja/")
               |> CurlReq.to_curl()
    end

    test "cookies get extracted from header" do
      assert Req.new(url: "http://example.com", headers: %{"cookie" => ["name1=value1"]})
             |> CurlReq.to_curl() ==
               "curl #{default_header()} -b \"name1=value1\" -X GET http://example.com"
    end

    test "works when body is iodata" do
      assert "curl #{default_header()} -d hello -X POST https://catfact.ninja/fact" ==
               Req.new(
                 method: :post,
                 url: "/fact",
                 base_url: "https://catfact.ninja",
                 body: ["h" | ["e" | ["llo"]]]
               )
               |> CurlReq.to_curl()
    end
  end

  describe "macro" do
    test "single header" do
      assert ~CURL(curl -H "user-agent: req/0.4.14" -X GET https://catfact.ninja/fact) ==
               %Req.Request{
                 method: :get,
                 headers: %{"user-agent" => ["req/0.4.14"]},
                 url: URI.parse("https://catfact.ninja/fact")
               }
    end

    test "post method" do
      assert ~CURL(curl -X POST https://example.com) ==
               %Req.Request{
                 method: :post,
                 url: URI.parse("https://example.com")
               }
    end

    test "head method" do
      assert ~CURL(curl -I https://example.com) ==
               %Req.Request{
                 method: :head,
                 url: URI.parse("https://example.com")
               }
    end

    test "multiple headers with body" do
      assert ~CURL(curl -H "accept-encoding: gzip" -H "authorization: Bearer 6e8f18e6-141b-4d12-8397-7e7791d92ed4:lon" -H "content-type: application/json" -H "user-agent: req/0.4.14" -d "{\"input\":[{\"leadFormFields\":{\"Company\":\"k\",\"Country\":\"DZ\",\"Email\":\"k\",\"FirstName\":\"k\",\"Industry\":\"CTO\",\"LastName\":\"k\",\"Phone\":\"k\",\"PostalCode\":\"1234ZZ\",\"jobspecialty\":\"engineer\",\"message\":\"I would like to know if Roche delivers to The Netherlands.\"}}],\"formId\":4318}" -X POST "https://example.com/rest/v1/leads/submitForm.json") ==
               %Req.Request{
                 method: :post,
                 url: URI.parse("https://example.com/rest/v1/leads/submitForm.json"),
                 headers: %{
                   "accept-encoding" => ["gzip"],
                   "authorization" => ["Bearer 6e8f18e6-141b-4d12-8397-7e7791d92ed4:lon"],
                   "content-type" => ["application/json"],
                   "user-agent" => ["req/0.4.14"]
                 },
                 body:
                   "{\"input\":[{\"leadFormFields\":{\"Company\":\"k\",\"Country\":\"DZ\",\"Email\":\"k\",\"FirstName\":\"k\",\"Industry\":\"CTO\",\"LastName\":\"k\",\"Phone\":\"k\",\"PostalCode\":\"1234ZZ\",\"jobspecialty\":\"engineer\",\"message\":\"I would like to know if Roche delivers to The Netherlands.\"}}],\"formId\":4318}"
               }
    end

    test "without curl prefix" do
      assert ~CURL(http://localhost) ==
               %Req.Request{
                 method: :get,
                 url: URI.parse("http://localhost")
               }
    end

    test "multiple data flags" do
      assert ~CURL(curl http://example.com -d name=foo -d mail=bar) ==
               %Req.Request{
                 url: URI.parse("http://example.com"),
                 body: "name=foo&mail=bar"
               }
    end

    test "cookie" do
      assert ~CURL(http://example.com -b "name1=value1") ==
               %Req.Request{
                 url: URI.parse("http://example.com"),
                 headers: %{"cookie" => ["name1=value1"]}
               }

      assert ~CURL(http://example.com -b "name1=value1; name2=value2") ==
               %Req.Request{
                 url: URI.parse("http://example.com"),
                 headers: %{"cookie" => ["name1=value1; name2=value2"]}
               }
    end

    test "formdata" do
      assert ~CURL(curl http://example.com -F name=foo -F mail=bar) ==
               %Req.Request{
                 url: URI.parse("http://example.com"),
                 body: nil,
                 registered_options: MapSet.new([:form]),
                 options: %{form: %{"name" => "foo", "mail" => "bar"}},
                 current_request_steps: [:encode_body],
                 request_steps: [encode_body: &Req.Steps.encode_body/1]
               }
    end

    test "redirects" do
      assert ~CURL(curl -L http://example.com) ==
               %Req.Request{
                 url: URI.parse("http://example.com"),
                 registered_options: MapSet.new([:redirect]),
                 options: %{redirect: true},
                 response_steps: [redirect: &Req.Steps.redirect/1]
               }
    end
  end
end
