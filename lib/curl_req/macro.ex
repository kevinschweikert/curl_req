defmodule CurlReq.Macro do
  @moduledoc false

  # TODO: handle newlines

  @parse_opts [
    strict: [
      header: :keep,
      request: :string,
      data: :keep,
      cookie: :string,
      head: :boolean,
      form: :keep,
      location: :boolean,
      user: :string
    ],
    aliases: [
      H: :header,
      X: :request,
      d: :data,
      b: :cookie,
      I: :head,
      F: :form,
      L: :location,
      u: :user
    ]
  ]

  @spec parse_opts() :: OptionParser.options()
  def parse_opts, do: @parse_opts

  @spec parse(String.t()) :: Req.Request.t()
  def parse(command) do
    command =
      command
      |> String.trim()
      |> String.trim_leading("curl")

    {options, [url], _invalid} =
      command
      |> OptionParser.split()
      |> OptionParser.parse(@parse_opts)

    url = String.trim(url)

    %Req.Request{}
    |> Req.merge(url: url)
    |> add_header(options)
    |> add_method(options)
    |> add_body(options)
    |> add_cookie(options)
    |> add_form(options)
    |> add_auth(options)
    |> configure_redirects(options)
  end

  defp add_header(req, options) do
    headers = Keyword.get_values(options, :header)

    for header <- headers, reduce: req do
      req ->
        [key, value] =
          header
          |> String.split(":", parts: 2)

        Req.Request.put_header(req, String.trim(key), String.trim(value))
    end
  end

  defp add_method(req, options) do
    method =
      if Keyword.get(options, :head, false) do
        :head
      else
        options
        |> Keyword.get(:request, "GET")
        |> String.downcase()
        |> String.to_existing_atom()
      end

    Req.merge(req, method: method)
  end

  defp add_body(req, options) do
    body =
      case Keyword.get_values(options, :data) do
        [] -> nil
        data -> Enum.join(data, "&")
      end

    Req.merge(req, body: body)
  end

  defp add_cookie(req, options) do
    case Keyword.get(options, :cookie) do
      nil -> req
      cookie -> Req.Request.put_header(req, "cookie", cookie)
    end
  end

  defp add_form(req, options) do
    case Keyword.get_values(options, :form) do
      [] ->
        req

      formdata ->
        form =
          for fd <- formdata, reduce: %{} do
            map ->
              [key, value] = String.split(fd, "=", parts: 2)
              Map.put(map, key, value)
          end

        req
        |> Req.Request.register_options([:form])
        |> Req.Request.prepend_request_steps(encode_body: &Req.Steps.encode_body/1)
        |> Req.merge(form: form)
    end
  end

  defp add_auth(req, options) do
    case Keyword.get(options, :user) do
      nil ->
        req

      credentials ->
        req
        |> Req.Request.register_options([:auth])
        |> Req.Request.prepend_request_steps(auth: &Req.Steps.auth/1)
        |> Req.merge(auth: {:basic, credentials})
    end
  end

  defp configure_redirects(req, options) do
    if Keyword.get(options, :location, false) do
      req
      |> Req.Request.register_options([:redirect])
      |> Req.Request.prepend_response_steps(redirect: &Req.Steps.redirect/1)
      |> Req.merge(redirect: true)
    else
      req
    end
  end
end
