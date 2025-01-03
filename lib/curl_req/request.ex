defmodule CurlReq.Request do
  @moduledoc since: "0.100"
  @moduledoc """
  This struct is a general abstraction over an HTTP request of an HTTP client.
  It acts as an intermediate representation to convert from and into the desired formats.
  """

  @doc "encode from the custom type to #{__MODULE__}"
  @callback encode(term(), Keyword.t()) :: __MODULE__.t()
  @doc "decode from #{__MODULE__} to the destination type"
  @callback decode(__MODULE__.t(), Keyword.t()) :: term()

  @type t() :: %__MODULE__{
          user_agent: user_agent(),
          headers: header(),
          cookies: cookie(),
          method: method(),
          url: URI.t(),
          compression: compression(),
          redirect: boolean(),
          proxy: boolean(),
          proxy_auth: auth(),
          auth: auth(),
          encoding: encoding(),
          body: term(),
          raw_body: term(),
          insecure: boolean()
        }

  @type user_agent() :: :curl | :req | String.t()
  @type header() :: %{optional(String.t()) => [String.t()]}
  @type cookie() :: %{optional(String.t()) => String.t()}
  @type auth() :: {auth_option(), String.t()} | auth_option()
  @type auth_option() :: :none | :basic | :bearer | :netrc
  @type encoding() :: :raw | :form | :json
  @type method() :: :get | :head | :put | :post | :delete | :patch
  @type compression() :: :none | :gzip | :br | :zstd

  @derive {Inspect, except: [:auth]}
  defstruct user_agent: :curl,
            headers: %{},
            cookies: %{},
            method: :get,
            url: URI.parse(""),
            compression: :none,
            redirect: false,
            proxy: false,
            proxy_url: URI.parse(""),
            proxy_auth: :none,
            auth: :none,
            encoding: :raw,
            body: nil,
            raw_body: nil,
            insecure: false

  @doc """
  Puts the header into the CurlReq.Request struct. Special headers like encoding, authorization or user-agent are stored in their respective field in the #{__MODULE__} struct instead of a general header.

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_header("X-GitHub-Api-Version", "2022-11-28")
      iex> request.headers
      %{"x-github-api-version" => ["2022-11-28"]}

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_header("Content-Type", "application/json")
      iex> request.encoding
      :json

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_header("Authorization", "Bearer foobar")
      iex> request.auth
      {:bearer, "foobar"}
  """
  @spec put_header(__MODULE__.t(), String.t(), String.t() | [String.t()]) :: __MODULE__.t()
  def put_header(%__MODULE__{} = request, key, [val]) do
    put_header(request, key, val)
  end

  def put_header(%__MODULE__{} = request, key, val) when is_binary(val) do
    key = String.downcase(key)

    case {key, val} do
      {"authorization", "Bearer " <> token} ->
        %{request | auth: {:bearer, token}}

      {"authorization", "Basic " <> userinfo} ->
        %{request | auth: {:basic, userinfo}}

      {"accept-encoding", compression}
      when compression in ["gzip", "br", "zstd"] ->
        put_compression(request, String.to_existing_atom(compression))

      {"content-type", "application/json"} ->
        %{request | encoding: :json}

      {"content-type", "application/x-www-form-urlencoded"} ->
        %{request | encoding: :form}

      {"user-agent", user_agent} ->
        put_user_agent(request, user_agent)

      {"cookie", cookies} ->
        for cookie <- String.split(cookies, ";"), reduce: request do
          request ->
            [key, value] = String.split(cookie, "=")
            put_cookie(request, key, value)
        end

      {key, val} ->
        headers = Map.put(request.headers, key, String.split(val, ";"))
        %{request | headers: headers}
    end
  end

  @doc """
  Puts the cookie into the CurlReq.Request struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_cookie("key1", "value1")
      iex> request.cookies
      %{"key1" => "value1"}
  """
  @spec put_cookie(__MODULE__.t(), String.t(), String.t()) :: __MODULE__.t()
  def put_cookie(%__MODULE__{} = request, key, value)
      when is_binary(key) and is_binary(value) do
    cookies = Map.put(request.cookies, key, value)
    %{request | cookies: cookies}
  end

  @doc """
  Puts the body and optional encoding into the CurlReq.Request struct
  It will immediately transform the input to the specified encoding when previously set.

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_body("some body")
      iex> request.encoding
      :raw
      iex> request.body
      "some body"

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_body(%{some: "body"})
      iex> request.body
      %{some: "body"}

      iex> request = %CurlReq.Request{} 
      ...> |> CurlReq.Request.put_encoding(:json) 
      ...> |> CurlReq.Request.put_body(~S|{"some": "body"}|)
      iex> request.body
      %{"some" => "body"}
  """
  @spec put_body(__MODULE__.t(), term()) :: __MODULE__.t()
  def put_body(%__MODULE__{} = request, nil), do: request

  def put_body(%__MODULE__{} = request, input) do
    body =
      case request.encoding do
        :json ->
          with true <- is_binary(input) or is_list(input),
               {:ok, json} <- Jason.decode(input) do
            json
          else
            _ -> input
          end

        _ ->
          input
      end

    %{request | body: body, raw_body: input}
  end

  @doc """
  Puts the body and optional encoding into the CurlReq.Request struct
  It will immediately transform the input to the specified encoding when previously set.

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_encoding(:json)
      iex> request.encoding
      :json

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_encoding(:form)
      iex> request.encoding
      :form

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_encoding(:raw)
      iex> request.encoding
      :raw

      iex> request = %CurlReq.Request{} 
      ...> |> CurlReq.Request.put_body(~S|{"foo": "bar"}|) 
      ...> |> CurlReq.Request.put_encoding(:json)
      iex> request.encoding
      :json
      iex> request.body
      %{"foo" =>  "bar"}
      iex> request = request |> CurlReq.Request.put_encoding(:raw)
      iex> request.body
      ~S|{"foo": "bar"}|
  """
  @spec put_encoding(__MODULE__.t(), encoding()) :: __MODULE__.t()
  def put_encoding(%__MODULE__{raw_body: raw_body} = request, encoding)
      when encoding in [:raw, :json, :form] do
    body =
      case encoding do
        :json ->
          with true <- is_binary(raw_body) or is_list(raw_body),
               {:ok, json} <- Jason.decode(raw_body) do
            json
          else
            _ -> raw_body
          end

        _ ->
          raw_body
      end

    %{request | body: body, encoding: encoding}
  end

  @doc """
  Puts authorization into the CurlReq.Request struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_auth({:basic, "barbaz"})
      iex> request.auth
      {:basic, "barbaz"}
  """
  @spec put_auth(__MODULE__.t(), {:bearer | :basic | :netrc, String.t()} | :netrc | nil) ::
          __MODULE__.t()
  def put_auth(%__MODULE__{} = request, nil) do
    request
  end

  def put_auth(%__MODULE__{} = request, :netrc) do
    %{request | auth: :netrc}
  end

  def put_auth(%__MODULE__{} = request, {_type, nil}) do
    request
  end

  def put_auth(%__MODULE__{} = request, {type, credentials})
      when type in [:netrc, :basic, :bearer] do
    %{request | auth: {type, credentials}}
  end

  @doc """
  Puts the url into the CurlReq.Request struct,
  It either accepts a binary or an URI struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_url("https://example.com")
      iex> request.url
      URI.parse("https://example.com")
  """
  @spec put_url(__MODULE__.t(), URI.t() | String.t()) :: __MODULE__.t()
  def put_url(%__MODULE__{} = request, %URI{scheme: scheme, userinfo: userinfo} = uri)
      when scheme in ["http", "https"] do
    request = %{request | url: uri}

    case userinfo do
      nil -> request
      userinfo -> %{request | auth: {:basic, userinfo}}
    end
  end

  def put_url(%__MODULE__{} = request, uri) when is_binary(uri) do
    with %URI{scheme: scheme, userinfo: userinfo} when scheme in ["http", "https"] <-
           URI.parse(uri) do
      request = %{
        request
        | url: URI.parse(uri) |> Map.put(:userinfo, nil)
      }

      case userinfo do
        nil -> request
        userinfo -> %{request | auth: {:basic, userinfo}}
      end
    end
  end

  @doc """
  Puts the proxy url into the CurlReq.Request struct,
  It either accepts a binary or an URI struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_proxy("https://example.com")
      iex> request.proxy_url
      URI.parse("https://example.com")
  """
  @spec put_proxy(__MODULE__.t(), URI.t() | String.t()) :: __MODULE__.t()
  def put_proxy(%__MODULE__{} = request, uri) do
    with %URI{scheme: scheme, userinfo: userinfo} when scheme in ["http", "https"] <-
           URI.parse(uri) do
      request = %{
        request
        | proxy_url: URI.parse(uri) |> Map.put(:userinfo, nil),
          proxy: true
      }

      case userinfo do
        nil -> request
        userinfo -> %{request | proxy_auth: {:basic, userinfo}}
      end
    else
      _ ->
        require Logger
        Logger.error(inspect(uri))
        request
    end
  end

  @doc """
  Puts the method into the CurlReq.Request struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_method("PUT")
      iex> request.method
      :put

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_method(:post)
      iex> request.method
      :post
  """
  @spec put_method(__MODULE__.t(), method() | String.t()) :: __MODULE__.t()
  def put_method(%__MODULE__{} = request, nil), do: request

  def put_method(%__MODULE__{} = request, method)
      when method in [:get, :head, :put, :post, :delete, :patch] do
    %{request | method: method}
  end

  def put_method(%__MODULE__{} = request, method) when is_binary(method) do
    method
    |> String.downcase()
    |> String.to_existing_atom()
    |> then(&put_method(request, &1))
  end

  @doc """
  Sets the compression option in the Curl.Request struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_compression(true)
      iex> request.compression
      :gzip

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_compression(:br)
      iex> request.compression
      :br
  """
  @spec put_compression(__MODULE__.t(), compression() | boolean() | nil) :: __MODULE__.t()
  def put_compression(%__MODULE__{} = request, nil), do: request

  def put_compression(%__MODULE__{} = request, true) do
    %{request | compression: :gzip}
  end

  def put_compression(%__MODULE__{} = request, false) do
    %{request | compression: :none}
  end

  def put_compression(%__MODULE__{} = request, type) when type in [:gzip, :br, :zstd] do
    %{request | compression: type}
  end

  @doc """
  Sets the insecure option in the Curl.Request struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_insecure(true)
      iex> request.insecure
      true
  """
  @spec put_insecure(__MODULE__.t(), boolean() | nil) :: __MODULE__.t()
  def put_insecure(%__MODULE__{} = request, nil), do: request

  def put_insecure(%__MODULE__{} = request, insecure) when is_boolean(insecure) do
    %{request | insecure: insecure}
  end

  @doc """
  Sets the redirect option in the Curl.Request struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_redirect(true)
      iex> request.redirect
      true
  """
  @spec put_redirect(__MODULE__.t(), boolean() | nil) :: __MODULE__.t()
  def put_redirect(%__MODULE__{} = request, nil), do: request

  def put_redirect(%__MODULE__{} = request, enabled) when is_boolean(enabled) do
    %{request | redirect: enabled}
  end

  @doc """
  Sets the  user agent in the Curl.Request struct

  ## Examples

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_user_agent(:req)
      iex> request.user_agent
      :req

      iex> request = %CurlReq.Request{} |> CurlReq.Request.put_user_agent("some user agent")
      iex> request.user_agent
      "some user agent"
  """
  @spec put_redirect(__MODULE__.t(), :req | :curl | String.t()) :: __MODULE__.t()
  def put_user_agent(%__MODULE{} = request, nil), do: request

  def put_user_agent(%__MODULE{} = request, "req/" <> _) do
    %{request | user_agent: :req}
  end

  def put_user_agent(%__MODULE{} = request, user_agent)
      when user_agent in [:curl, :req] or is_binary(user_agent) do
    %{request | user_agent: user_agent}
  end
end
