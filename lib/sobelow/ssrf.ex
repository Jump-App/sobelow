defmodule Sobelow.SSRF do
  @moduledoc """
  # Server-Side Request Forgery

  Requests to user-controlled destinations may expose internal services or
  credentials. Validate destinations against an allow-list, including redirects.

  Learn more about the HTTP client check with:

      $ mix sobelow -d SSRF.HTTPClient

  Ignore all SSRF checks with:

      $ mix sobelow -i SSRF
  """
  @submodules [Sobelow.SSRF.HTTPClient]
  use Sobelow.FindingType

  def get_vulns(fun, meta_file, _web_root, skip_mods \\ []) do
    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)
    Enum.each(allowed, & &1.run(fun, meta_file))
  end
end
