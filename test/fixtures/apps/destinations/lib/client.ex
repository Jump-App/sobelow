defmodule Destinations.Client do
  def fetch(conn, url) do
    url |> Req.get!()
    conn |> Plug.Conn.put_resp_header("location", url)
  end
end
