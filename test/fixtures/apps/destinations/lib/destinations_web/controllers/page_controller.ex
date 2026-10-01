defmodule DestinationsWeb.PageController do
  use DestinationsWeb, :controller

  def fetch(conn, %{"url" => url}) do
    Req.get(url: url)
    Tesla.get(url)
    Mint.HTTP.connect(:https, url, 443)
    redirect(conn, external: url)
  end

  def indirect(conn, _params) do
    url = destination()
    HTTPoison.request(:get, url)
    put_resp_header(conn, "location", url)
  end

  def safe(conn, params) do
    Req.post(url: "https://example.com", json: params)
    Tesla.post("https://example.com", params)
    Mint.HTTP.request(conn, "GET", params["path"], [], nil)
    redirect(conn, to: params["path"])
  end

  # sobelow_skip ["SSRF.HTTPClient", "Misc.OpenRedirect"]
  def skipped(conn, %{"url" => url}) do
    Finch.build(:get, url)
    redirect(conn, external: url)
  end
end
