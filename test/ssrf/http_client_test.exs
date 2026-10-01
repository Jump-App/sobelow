defmodule SobelowTest.SSRF.HTTPClientTest do
  use ExUnit.Case, async: true

  alias Sobelow.SSRF.HTTPClient

  for call <- [
        "HTTPoison.get(url)",
        "HTTPoison.post!(url, body)",
        "HTTPoison.request(:get, url)",
        "HTTPoison.request!(:post, url, body)",
        "url |> HTTPoison.get()",
        ":get |> HTTPoison.request(url)",
        "Finch.build(:get, url)",
        ":get |> Finch.build(url)",
        "Req.get(url)",
        "Req.post!(url: url, body: body)",
        "Req.request(method: :get, url: url)",
        "Req.get(request, url: url)",
        "[url: url, body: body] |> Req.get!()",
        "request |> Req.get(url: url)",
        ~S'Req.get("https://example.com", url: url)',
        "Tesla.get(url)",
        "Tesla.get!(url, query: [page: body])",
        "Tesla.get(client, url)",
        "Tesla.get(client(), url)",
        "Tesla.get(MyApi.client(), url)",
        "Tesla.get(build_client(), url)",
        "Tesla.get(c, url)",
        "Tesla.get(api_client, url, query: [page: body])",
        "url |> Tesla.get!()",
        "client |> Tesla.get(url)",
        "Tesla.post(url, body)",
        "Tesla.post!(url, body, query: [page: 1])",
        "Tesla.post(client, url, body)",
        "Tesla.post(client(), url, body)",
        "Tesla.post(c, url, body)",
        "Tesla.post!(client, url, body, [])",
        "Tesla.request(method: :get, url: url, body: body)",
        "Tesla.request!(client, url: url, body: body)",
        "Mint.HTTP.connect(:https, url, 443)",
        ":https |> Mint.HTTP.connect(url, 443)",
        "Mint.HTTP1.connect(:http, url, 80, [])",
        "Mint.HTTP2.connect(:https, url, 443, [])",
        ~S'Mint.HTTP.request(conn, "CONNECT", url, [], nil)',
        ~S'Mint.HTTP2.request(conn, "CONNECT", url, [], nil)'
      ] do
    test "selects only the destination in #{call}" do
      ast = Code.string_to_quoted!("def index(conn, url, body, request), do: #{unquote(call)}")
      assert {[{_, [:url]}], _, {:index, 1}} = HTTPClient.parse_def(ast)
    end
  end

  for call <- [
        ~S'HTTPoison.get("https://example.com", headers, options)',
        ~S'HTTPoison.post!("https://example.com", body)',
        ~S'HTTPoison.request(method, "https://example.com", body)',
        ~S'Finch.build(method, "https://example.com", headers, body)',
        ~S'Req.post!(url: "https://example.com", json: params)',
        ~S'[url: "https://example.com", body: body] |> Req.post!()',
        ~S'Req.get(url, url: "https://example.com")',
        ~S'Req.get(%Req.Request{url: "https://example.com", body: body})',
        "Req.post(json: params)",
        "Other.get(url)",
        "get(url)",
        "HTTPoison.get()",
        "HTTPoison.request(request)",
        "Req.get([{:url}])",
        ~S'Tesla.get("https://example.com", query: [page: params])',
        ~S'Tesla.get(client, "https://example.com")',
        ~S'Tesla.get(c, "https://example.com")',
        ~S'Tesla.get(client(), "/users")',
        ~S'Tesla.get(MyApi.client(), "/users")',
        ~S'Tesla.post("https://example.com", params)',
        ~S'Tesla.post(client, "https://example.com", params)',
        ~S'Tesla.request(method: :post, url: "https://example.com", body: params)',
        "Tesla.request(method: :post, body: params)",
        ~S'Mint.HTTP.connect(:https, "example.com", port)',
        ~S'Mint.HTTP.request(conn, "GET", params, [], nil)',
        ~S'Mint.HTTP.request(conn, "CONNECT", "example.com:443", [], nil)',
        "Other.connect(:https, params, 443)"
      ] do
    test "does not flag #{call}" do
      ast = Code.string_to_quoted!("def index(conn, params), do: #{unquote(call)}")
      assert {[], _, _} = HTTPClient.parse_def(ast)
    end
  end

  test "recognizes conn.params, interpolation, captures and unknown expressions" do
    for {expression, variable} <- [
          {~S'HTTPoison.get(conn.params["url"])', "conn.params"},
          {~S'HTTPoison.get("https://example.com/#{url}")', :url},
          {"Enum.map(urls, &HTTPoison.get/1)", "&1"},
          {"Enum.map(urls, &Req.get(url: &1))", "&1"},
          {"Req.get(@destination)", "@destination"},
          {"Req.get(destination())", "destination()"},
          {~S'Req.get(Access.get(%{"url" => url}, "url"))', :url}
        ] do
      ast = Code.string_to_quoted!("def index(conn, url), do: #{expression}")
      assert {[{_, [^variable]}], _, _} = HTTPClient.parse_def(ast)
    end
  end

  test "opaque Req options can override a literal URL" do
    ast =
      Code.string_to_quoted!(~S'def index(conn, opts), do: Req.get("https://example.com", opts)')

    assert {[{_, [:opts]}], _, _} = HTTPClient.parse_def(ast)
  end

  test "Tesla direct calls do not mistake dynamic options or bodies for URLs" do
    for expression <- [
          "Tesla.get(url, opts)",
          "Tesla.post(url, body, opts)"
        ] do
      ast = Code.string_to_quoted!("def index(conn, url, opts, body), do: #{expression}")
      assert {[{_, [:url]}], _, _} = HTTPClient.parse_def(ast)
    end
  end

  test "Tesla client factory is not reported as a destination" do
    ast = Code.string_to_quoted!("def index(conn, path), do: Tesla.get(client(), path)")
    assert {[{_, [:path]}], _, _} = HTTPClient.parse_def(ast)
  end

  test "Tesla request conservatively flags opaque option lists" do
    for expression <- ["Tesla.request(opts)", "Tesla.request!(client, opts)"] do
      ast = Code.string_to_quoted!("def index(conn, client, opts), do: #{expression}")
      assert {[{_, [:opts]}], _, _} = HTTPClient.parse_def(ast)
    end
  end

  test "retains the original piped call and its location exactly once" do
    ast =
      Code.string_to_quoted!(
        """
        def index(conn, url) do
          url
          |> Req.get!()
        end
        """,
        columns: true
      )

    {[{call, [:url]}], _, _} = HTTPClient.parse_def(ast)
    assert Macro.to_string(call) == "Req.get!()"
    assert Sobelow.Parse.get_fun_line(call) == 3
    assert Sobelow.Parse.get_fun_column(call) > 0
  end

  test "finds nested calls without duplicating pipe stages" do
    ast =
      Code.string_to_quoted!("""
      def index(conn, url) do
        url |> Req.get!() |> consume(HTTPoison.get(url))
      end
      """)

    assert {findings, _, _} = HTTPClient.parse_def(ast)
    assert length(findings) == 2
  end
end
