defmodule CurlReq.Curl do
  @moduledoc """
  Implements the `CurlReq.Request` behaviour for a cURL command string
  """

  @behaviour CurlReq.Request

  defmodule Flag do
    defstruct [:short, :long, :type, :doc]
  end

  @flags [
    [long: :header, short: :H, type: :keep, doc: "HTTP Header flag"],
    [long: :request, short: :X, type: :string, doc: "Specify request method"],
    [long: :data, short: :d, type: :keep, doc: "HTTP POST data"],
    [long: :data_raw, short: nil, type: :keep, doc: "Raw HTTP POST data"],
    [long: :data_ascii, short: nil, type: :keep, doc: "ASCII HTTP POST data"],
    [long: :cookie, short: :b, type: :string, doc: "Cookie string"],
    [long: :head, short: :I, type: :boolean, doc: "Show document info only"],
    [long: :form, short: :F, type: :keep, doc: "Specify HTTP multipart POST data"],
    [long: :location, short: :L, type: :boolean, doc: "Follow redirects"],
    [long: :user, short: :u, type: :string, doc: "Server user and password"],
    [long: :compressed, short: nil, type: :boolean, doc: "Request compressed response"],
    [long: :proxy, short: :x, type: :string, doc: "Use proxy"],
    [long: :proxy_user, short: :U, type: :string, doc: "Proxy user and password"],
    [long: :netrc, short: :n, type: :boolean, doc: "Must read .netrc for user/password"],
    [long: :netrc_file, short: nil, type: :string, doc: "Specify alternative .netrc file"],
    [long: :insecure, short: :k, type: :boolean, doc: "Allow insecure server connections"],
    [long: :user_agent, short: :A, type: :string, doc: "Send User-Agent string"]
  ]

  def options() do
    @flags
    |> Enum.map(fn flag -> {flag[:long], flag[:type]} end)
  end

  def aliases() do
    @flags
    |> Enum.map(fn flag -> {flag[:short], flag[:long]} end)
    |> Enum.reject(fn {short, _} -> is_nil(short) end)
  end

  @doc """
  Lists supported flags for the cURL command

  ## Examples

      iex> flags = CurlReq.Curl.flags()
      iex> {:header, :H} in flags
      true

      iex> flags = CurlReq.Curl.flags()
      iex> {:compressed, nil} in flags
      true

      iex> flags = CurlReq.Curl.flags()
      iex> {:foo, nil} in flags
      false
  """
  @spec flags() :: [{atom(), atom() | nil}]
  def flags do
    @flags
  end

  @impl CurlReq.Request
  @spec decode(String.t()) :: CurlReq.Request.t()
  def decode(command, _opts \\ []) when is_binary(command) do
    command =
      command
      |> String.trim()
      |> String.trim_leading("curl")
      |> CurlReq.Shell.remove_newlines()

    {options, rest, invalid} =
      command
      |> OptionParser.split()
      |> OptionParser.parse(
        strict: options(),
        aliases: aliases()
      )

    if invalid != [] do
      errors =
        Enum.map(invalid, fn
          {flag, nil} -> "Unknown #{inspect(flag)}"
          {flag, value} -> "Invalid value #{inspect(value)} for #{inspect(flag)}"
        end)
        |> Enum.join("\n")

      raise ArgumentError, """

      Command: \'curl #{command}\"
      Unsupported or invalid flag(s) encountered:

      #{errors}

      Please remove the unknown flags and open an issue at https://github.com/derekkraan/curl_req
      """
    end

    [url] =
      rest
      |> List.flatten()

    url = URI.parse(url)

    %CurlReq.Request{}
    |> CurlReq.Request.put_url(url)
    |> add_header(options)
    |> add_method(options)
    |> add_body(options)
    |> add_cookie(options)
    |> add_form(options)
    |> add_auth(options)
    |> add_compression(options)
    |> add_proxy(options)
    |> add_insecure(options)
    |> add_user_agent(options)
    |> configure_redirects(options)
  end

  defp add_header(request, options) do
    headers = Keyword.get_values(options, :header)

    Enum.reduce(headers, request, fn header, acc ->
      [key, value] =
        header
        |> String.split(":", parts: 2)
        |> Enum.map(&String.trim/1)

      CurlReq.Request.put_header(acc, key, value)
    end)
  end

  defp add_method(request, options) do
    CurlReq.Request.put_method(request, (options[:head] && :head) || options[:request])
  end

  defp add_body(request, options) do
    body =
      Enum.flat_map([:data, :data_ascii, :data_raw], fn key ->
        case Keyword.get_values(options, key) do
          [] -> []
          values -> Enum.map(values, &String.trim_leading(&1, "$"))
        end
      end)
      |> Enum.join("&")

    if body != "" do
      CurlReq.Request.put_body(request, body)
    else
      request
    end
  end

  defp add_cookie(request, options) do
    case Keyword.get(options, :cookie) do
      nil ->
        request

      cookie ->
        String.split(cookie, ";")
        |> Enum.reduce(request, fn cookie, acc ->
          [key, value] =
            String.split(cookie, "=", parts: 2)
            |> Enum.map(&String.trim/1)

          CurlReq.Request.put_cookie(acc, key, value)
        end)
    end
  end

  defp add_form(request, options) do
    case Keyword.get_values(options, :form) do
      [] ->
        request

      formdata ->
        form =
          for fd <- formdata, reduce: %{} do
            map ->
              [key, value] = String.split(fd, "=", parts: 2)
              Map.put(map, key, value)
          end

        request
        |> CurlReq.Request.put_body(form)
        |> CurlReq.Request.put_encoding(:form)
    end
  end

  defp add_auth(request, options) do
    request
    |> CurlReq.Request.put_auth({:basic, options[:user]})
    |> CurlReq.Request.put_auth(options[:netrct])
    |> CurlReq.Request.put_auth({:netrc, options[:netrc_file]})
  end

  defp add_compression(request, options) do
    CurlReq.Request.put_compression(request, options[:compressed])
  end

  defp add_proxy(request, options) do
    proxy = Keyword.get(options, :proxy)
    proxy_user = Keyword.get(options, :proxy_user)

    case {proxy, proxy_user} do
      {nil, _} ->
        request

      {proxy, nil} ->
        proxy = validate_proxy_uri(proxy)
        CurlReq.Request.put_proxy(request, proxy)

      {proxy, proxy_user} ->
        proxy = validate_proxy_uri(proxy)
        proxy = %{proxy | userinfo: proxy_user}
        CurlReq.Request.put_proxy(request, proxy)
    end
  end

  defp validate_proxy_uri("http://" <> _rest = uri), do: URI.parse(uri)
  defp validate_proxy_uri("https://" <> _rest = uri), do: URI.parse(uri)

  defp validate_proxy_uri(uri) do
    case String.split(uri, "://") do
      [scheme, _uri] ->
        raise ArgumentError, "Unsupported scheme #{scheme} for proxy in #{uri}"

      [uri] ->
        URI.parse("http://" <> uri)
    end
  end

  defp add_insecure(request, options) do
    CurlReq.Request.put_insecure(request, options[:insecure])
  end

  defp add_user_agent(request, options) do
    CurlReq.Request.put_user_agent(request, options[:user_agent])
  end

  defp configure_redirects(request, options) do
    CurlReq.Request.put_redirect(request, options[:location])
  end

  @impl CurlReq.Request
  @spec encode(CurlReq.Request.t(), Keyword.t()) :: String.t()
  def encode(%CurlReq.Request{} = request, options \\ []) do
    options =
      Keyword.validate!(options, flags: :short, flavor: :curl)

    flag_style = options[:flags]
    flavor = options[:flavor]

    cookies =
      if map_size(request.cookies) != 0 do
        request.cookies
        |> Enum.map(fn {key, val} -> "#{key}=#{val}" end)
        |> Enum.join(";")
      else
        []
      end

    cookies = emit_if(cookies != [], [cookie_flag(flag_style, cookies)])

    headers =
      for {key, values} <- request.headers, reduce: [] do
        headers ->
          [headers, header_flag(flag_style, [key, ": ", Enum.intersperse(values, ";")])]
      end

    headers =
      case request.encoding do
        :raw ->
          headers

        :json ->
          headers ++ [header_flag(flag_style, "content-type: application/json")]

        :form ->
          headers ++ [header_flag(flag_style, "content-type: application/x-www-form-urlencoded")]
      end

    user_agent =
      case {flavor, request.user_agent} do
        {:curl, agent} when is_atom(agent) -> []
        {:req, :curl} -> []
        {:req, :req} -> [user_agent_flag(flag_style, ["req/", CurlReq.req_version()])]
        {_, user_agent} -> [user_agent_flag(flag_style, user_agent)]
      end

    body =
      emit_if(request.body, fn ->
        case request.encoding do
          :json -> [data_flag(flag_style, Jason.encode!(request.body))]
          _ -> [data_flag(flag_style, request.body)]
        end
      end)

    redirect = emit_if(request.redirect, [location_flag(flag_style)])

    compressed =
      emit_if(request.compression != :none, fn ->
        case flavor do
          :curl ->
            [compressed_flag(flag_style)]

          :req ->
            [
              header_flag(flag_style, ["accept-encoding: ", Atom.to_string(request.compression)])
            ]
        end
      end)

    auth =
      case request.auth do
        :none ->
          []

        {:basic, userinfo} ->
          user_flag(flag_style, userinfo)

        {:bearer, token} ->
          [header_flag(flag_style, ["authorization: Bearer ", token])]

        :netrc ->
          [netrc_flag(flag_style)]

        {:netrc, filepath} ->
          [netrc_file_flag(flag_style, filepath)]
      end

    method =
      case request.method do
        :head -> [head_flag(flag_style)]
        m -> [request_flag(flag_style, String.upcase(to_string(m)))]
      end

    proxy =
      if request.proxy do
        proxy_flag(flag_style, URI.to_string(request.proxy_url))
      else
        []
      end

    proxy_auth =
      case request.proxy_auth do
        :none -> []
        {:basic, userinfo} -> proxy_user_flag(flag_style, userinfo)
        _ -> []
      end

    insecure = if request.insecure, do: [insecure_flag(flag_style)], else: []

    url = [" ", to_string(request.url)]

    IO.iodata_to_binary([
      "curl",
      compressed,
      insecure,
      auth,
      headers,
      user_agent,
      cookies,
      body,
      proxy,
      proxy_auth,
      redirect,
      method,
      url
    ])
  end

  defp emit_if(bool, fun) when is_function(fun) do
    if bool, do: fun.(), else: []
  end

  defp emit_if(bool, value) do
    if bool, do: value, else: []
  end

  defp escape(value) when is_list(value) do
    IO.iodata_to_binary(value) |> escape()
  end

  defp escape(value) when is_binary(value) do
    CurlReq.Shell.escape(value)
  end

  defp cookie_flag(:short, value), do: [" -b ", escape(value)]
  defp cookie_flag(:long, value), do: [" --cookie ", escape(value)]

  defp header_flag(:short, value), do: [" -H ", escape(value)]
  defp header_flag(:long, value), do: [" --header ", escape(value)]

  defp data_flag(:short, value), do: [" -d ", escape(value)]
  defp data_flag(:long, value), do: [" --data ", escape(value)]

  defp head_flag(:short), do: " -I"
  defp head_flag(:long), do: " --head"

  defp request_flag(:short, value), do: [" -X ", escape(value)]
  defp request_flag(:long, value), do: [" --request ", escape(value)]

  defp location_flag(:short), do: " -L"
  defp location_flag(:long), do: " --location"

  defp user_flag(:short, value), do: [" -u ", escape(value)]
  defp user_flag(:long, value), do: [" --user ", escape(value)]

  defp netrc_flag(:short), do: " -n"
  defp netrc_flag(:long), do: " --netrc"

  defp netrc_file_flag(_, value), do: [" --netrc-file ", escape(value)]

  defp compressed_flag(_), do: " --compressed"

  defp proxy_flag(:short, value), do: [" -x ", escape(value)]
  defp proxy_flag(:long, value), do: [" --proxy ", escape(value)]

  defp proxy_user_flag(:short, value), do: [" -U ", escape(value)]
  defp proxy_user_flag(:long, value), do: [" --proxy-user ", escape(value)]

  defp insecure_flag(:short), do: " -k"
  defp insecure_flag(:long), do: " --insecure"

  defp user_agent_flag(:short, value), do: [" -A ", escape(value)]
  defp user_agent_flag(:long, value), do: [" --user-agent ", escape(value)]
end
