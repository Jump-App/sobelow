defmodule SobelowTest.Misc.OpenRedirectTest do
  use ExUnit.Case, async: true

  alias Sobelow.Misc.OpenRedirect

  for call <- [
        "redirect(conn, external: url)",
        "conn |> redirect(external: url)",
        "Phoenix.Controller.redirect(conn, external: url)",
        "conn |> Controller.redirect(external: url)",
        ~S'put_resp_header(conn, "location", url)',
        ~S'conn |> Plug.Conn.put_resp_header("location", url)',
        ~S'Conn.put_resp_header(conn, "Location", url)'
      ] do
    test "finds #{call}" do
      ast = Code.string_to_quoted!("def index(conn, url), do: #{unquote(call)}")
      assert {[{_, [:url]}], _, _} = OpenRedirect.parse_def(ast)
    end
  end

  for call <- [
        "redirect(conn, to: url)",
        ~S'redirect(conn, external: "https://example.com", other: url)',
        ~S'conn |> redirect(external: "https://example.com")',
        ~S'put_resp_header(conn, "location", "/home")',
        ~S'put_resp_header(conn, "x-custom", url)',
        "Other.redirect(conn, external: url)",
        "redirect(conn, options)",
        "redirect(conn, [{:external}])"
      ] do
    test "does not flag #{call}" do
      ast = Code.string_to_quoted!("def index(conn, url), do: #{unquote(call)}")
      assert {[], _, _} = OpenRedirect.parse_def(ast)
    end
  end
end
