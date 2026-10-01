defmodule Sobelow.Misc.OpenRedirect do
  @moduledoc """
  # Potential Open Redirect

  Detects dynamic `external:` destinations in Phoenix.Controller.redirect/2
  and dynamic Location values in Plug.Conn.put_resp_header/3. Unqualified calls
  and the conventional Controller/Conn aliases are also checked, so unrelated
  local functions with these names may produce false positives.

  Prefer Phoenix's `to:` option for local paths. When an external redirect is
  necessary, validate its scheme, host and port against an allow-list. Literal
  destinations are not reported. A Location header alone does not prove that
  the response is a redirect; review its status and surrounding code.

  Literal option lists are inspected; options assembled elsewhere and renamed
  module aliases are not resolved. Assignments and validation are not traced.

  Ignore this check with:

      $ mix sobelow -i Misc.OpenRedirect
  """
  @uid 33
  @finding_type "Misc.OpenRedirect: Potential Open Redirect"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding/1)
  end

  @doc false
  def parse_def(fun), do: Parse.get_selected_fun_vars_and_meta(fun, &destination/1)

  defp destination({{:., _, [{:__aliases__, _, module}, :redirect]}, meta, args})
       when module in [[:Phoenix, :Controller], [:Controller]],
       do: destination({:redirect, meta, args})

  defp destination({{:., _, [{:__aliases__, _, module}, :put_resp_header]}, meta, args})
       when module in [[:Plug, :Conn], [:Conn]],
       do: destination({:put_resp_header, meta, args})

  # redirect(conn, options): select :external from the options at index 1.
  defp destination({:redirect, _, [_, options]}) when is_list(options) do
    if Keyword.keyword?(options), do: Keyword.fetch(options, :external), else: :error
  end

  # put_resp_header(conn, name, value): Location value at index 2.
  defp destination({:put_resp_header, _, [_, header, value]}) when is_binary(header) do
    if String.downcase(header) == "location", do: {:ok, value}, else: :error
  end

  defp destination(_), do: :error
end
