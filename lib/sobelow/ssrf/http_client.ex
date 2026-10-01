defmodule Sobelow.SSRF.HTTPClient do
  @moduledoc """
  # Potential Server-Side Request Forgery in HTTP clients

  Detects dynamic destinations in HTTPoison, Req, Finch, Tesla and Mint calls, including
  pipelines. A finding indicates a destination that needs review, not proof
  that an attacker can reach an internal service. Validate scheme, host and port
  against an allow-list and enforce the same restrictions on redirects.

  HTTPoison verb helpers and positional request/request! calls, Req verb helpers
  and request/request! calls (including literal `url:` options), Finch.build,
  Tesla verb helpers and request/request!, and Mint.HTTP.connect and CONNECT
  requests are supported. Finch.build constructs a request; it need not be sent
  locally. Mint request paths are not destinations for ordinary requests.

  Some Tesla verb calls can mean either `(url, options)` or `(client, url)`.
  Client calls are recognized when the client is a Tesla.Client struct, a
  `client()` or `*_client()` call, a variable named `client` or `*_client`, or
  the second argument is visibly a URL. Other ambiguous calls use the first
  argument as the URL. Renamed aliases, custom client wrappers, destinations
  stored in request structs, module attributes and Req base_url configuration
  are not resolved.
  Opaque Req and Tesla options are reported conservatively; options or request
  objects built elsewhere may produce false positives.

  Confidence follows direct parameter use in controllers. Assignments and
  validation in other functions are not traced. Fixed-host interpolations may
  still be reported; review whether input can alter the destination.

  Ignore this check with:

      $ mix sobelow -i SSRF.HTTPClient
  """
  @uid 32
  @finding_type "SSRF.HTTPClient: Potential Server-Side Request Forgery in HTTP client"
  @verbs [
    :get,
    :get!,
    :head,
    :head!,
    :post,
    :post!,
    :put,
    :put!,
    :patch,
    :patch!,
    :delete,
    :delete!,
    :options,
    :options!
  ]
  @tesla_simple [
    :get,
    :get!,
    :head,
    :head!,
    :delete,
    :delete!,
    :options,
    :options!,
    :trace,
    :trace!
  ]
  @tesla_body [:post, :post!, :put, :put!, :patch, :patch!, :query, :query!]
  @mint_modules [[:Mint, :HTTP], [:Mint, :HTTP1], [:Mint, :HTTP2]]

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding/1)
  end

  @doc false
  def parse_def(fun), do: Parse.get_selected_fun_vars_and_meta(fun, &destination/1)

  # HTTPoison.get(url, headers \\ [], options \\ []), etc.: URL at index 0.
  defp destination({{:., _, [{:__aliases__, _, [:HTTPoison]}, verb]}, _, [url | _]})
       when verb in @verbs,
       do: {:ok, url}

  # HTTPoison.request(method, url, body \\ "", headers \\ [], options \\ []): index 1.
  defp destination({{:., _, [{:__aliases__, _, [:HTTPoison]}, name]}, _, [_, url | _]})
       when name in [:request, :request!],
       do: {:ok, url}

  # Finch.build(method, url, headers \\ [], body \\ nil, opts \\ []): index 1.
  defp destination({{:., _, [{:__aliases__, _, [:Finch]}, :build]}, _, [_, url | _]}),
    do: {:ok, url}

  # Req.get(url_or_options_or_request, options \\ []): options can override URL.
  defp destination({{:., _, [{:__aliases__, _, [:Req]}, name]}, _, [first | rest]})
       when name in @verbs or name in [:request, :request!] do
    req_destination(first, rest)
  end

  # Tesla.get(url, opts) and Tesla.get(client, url, opts): the client is optional.
  defp destination({{:., _, [{:__aliases__, _, [:Tesla]}, name]}, _, args})
       when name in @tesla_simple and is_list(args),
       do: tesla_destination(args, :simple)

  # Tesla.post(url, body, opts) and Tesla.post(client, url, body, opts).
  defp destination({{:., _, [{:__aliases__, _, [:Tesla]}, name]}, _, args})
       when name in @tesla_body and is_list(args),
       do: tesla_destination(args, :body)

  # Tesla.request(options) and Tesla.request(client, options): URL is an option.
  defp destination({{:., _, [{:__aliases__, _, [:Tesla]}, name]}, _, args})
       when name in [:request, :request!] and is_list(args),
       do: tesla_request_destination(args)

  # Mint.HTTP.connect(scheme, address, port, opts): address is the destination.
  defp destination({{:., _, [{:__aliases__, _, module}, :connect]}, _, [_, host, _ | _]})
       when module in @mint_modules,
       do: {:ok, host}

  # Mint.HTTP.request(conn, method, path, headers, body): only CONNECT's path
  # identifies a new network destination rather than a path on the connection.
  defp destination(
         {{:., _, [{:__aliases__, _, module}, :request]}, _, [_, "CONNECT", target, _, _]}
       )
       when module in @mint_modules,
       do: {:ok, target}

  defp destination(_), do: :error

  defp tesla_destination([url], :simple), do: {:ok, url}

  defp tesla_destination([first, second], :simple), do: tesla_verb_destination(first, second)

  defp tesla_destination([_, url, _], :simple), do: {:ok, url}
  defp tesla_destination([url, _body], :body), do: {:ok, url}

  defp tesla_destination([first, second, _body_or_opts], :body),
    do: tesla_verb_destination(first, second)

  defp tesla_destination([_, url, _, _], :body), do: {:ok, url}
  defp tesla_destination(_, _), do: :error

  defp tesla_verb_destination(first, second) do
    if tesla_client?(first) or (not tesla_url?(first) and tesla_url?(second)),
      do: {:ok, second},
      else: {:ok, first}
  end

  defp tesla_request_destination([options]), do: tesla_request_opts(options)
  defp tesla_request_destination([_, options]), do: tesla_request_opts(options)
  defp tesla_request_destination(_), do: :error

  defp tesla_request_opts(options) when is_list(options), do: keyword_url(options)
  defp tesla_request_opts(options), do: {:ok, options}

  defp tesla_client?({:%, _, [{:__aliases__, _, [:Tesla, :Client]}, _]}), do: true
  defp tesla_client?({{:., _, [{:__aliases__, _, [:Tesla]}, :client]}, _, _}), do: true

  defp tesla_client?({{:., _, [_, name]}, _, args}) when is_atom(name) and is_list(args),
    do: client_name?(name)

  defp tesla_client?({name, _, args}) when is_atom(name) and is_list(args),
    do: client_name?(name)

  defp tesla_client?({name, _, context}) when is_atom(name) and is_atom(context) do
    client_name?(name)
  end

  defp tesla_client?(_), do: false

  defp client_name?(name) do
    name = Atom.to_string(name)
    name == "client" or String.ends_with?(name, "_client")
  end

  defp tesla_url?({name, _, context}) when is_atom(name) and is_atom(context),
    do: name in [:url, :uri, :destination, :endpoint]

  defp tesla_url?(value) when is_binary(value), do: true
  defp tesla_url?({:<<>>, _, _}), do: true

  defp tesla_url?({{:., _, [Access, :get]}, _, [_, key]}) when key in ["url", :url],
    do: true

  defp tesla_url?(_), do: false

  # An opaque options argument may override even a literal URL.
  defp req_destination(first, [options]) when not is_list(options) do
    case req_destination(first) do
      {:ok, url} -> {:ok, [url, options]}
      :error -> {:ok, options}
    end
  end

  defp req_destination(first, rest) do
    case keyword_url(List.first(rest)) do
      {:ok, _} = result -> result
      :error -> req_destination(first)
    end
  end

  defp req_destination(options) when is_list(options), do: keyword_url(options)
  defp req_destination({:%, _, _}), do: :error
  defp req_destination(value), do: {:ok, value}

  defp keyword_url(options) when is_list(options) do
    if Keyword.keyword?(options), do: Keyword.fetch(options, :url), else: :error
  end

  defp keyword_url(_), do: :error
end
