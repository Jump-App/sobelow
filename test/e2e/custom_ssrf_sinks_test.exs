defmodule SobelowTest.CustomSSRFSinksTest do
  use Sobelow.ScanCase, async: false
  import ExUnit.CaptureIO
  alias Sobelow.SSRF.CustomSinks

  @sinks [[module: "MyApp.HTTP", function: "fetch", arity: 2, url_arg: 1]]

  test "matches direct, aliased, imported and piped calls with exact signatures" do
    temp_fixture_file("basic", "lib/basic_web/controllers/wrapper_controller.ex", """
    defmodule BasicWeb.WrapperController do
      use BasicWeb, :controller
      alias MyApp.HTTP, as: Client
      import MyApp.HTTP, only: [fetch: 2]
      def index(conn, url) do
        MyApp.HTTP.fetch(conn, url)
        Client.fetch(conn, url)
        conn |> Client.fetch(url)
        fetch(conn, url)
        conn |> fetch(url)
        MyApp.HTTP.fetch(conn, "https://example.com")
        MyApp.HTTP.fetch(url)
        Other.fetch(conn, url)
        Req.get(url)
      end
    end
    """)

    found = scan("basic", ssrf_sinks: @sinks) |> findings_for("SSRF.HTTPClient")
    assert length(found) == 6
    assert Enum.all?(found, &(&1["confidence"] == "high"))
    assert Enum.sort(Enum.map(found, & &1["line"])) == [6, 7, 8, 9, 10, 14]

    assert [] =
             scan("basic", ssrf_sinks: @sinks, ignored: ["SSRF.HTTPClient"])
             |> findings_for("SSRF.HTTPClient")

    assert [_] = scan("basic") |> findings_for("SSRF.HTTPClient")
  end

  test "reads configuration through the CLI and resets it with --no-config" do
    temp_fixture_file("basic", "lib/wrapper.ex", """
    defmodule Wrapper do
      def request(url), do: MyApp.HTTP.fetch(:client, url)
    end
    """)

    temp_fixture_file("basic", ".sobelow-conf", inspect(ssrf_sinks: @sinks))
    args = ["--root", fixture_path("basic"), "--private", "--format", "json"]
    output = capture_io(fn -> Mix.Tasks.Sobelow.run(args) end)
    assert [_] = output |> Jason.decode!() |> findings_for("SSRF.HTTPClient")
    path = Path.join(fixture_path("basic"), ".sobelow-conf")
    capture_io("y\n", fn -> Sobelow.save_config(path) end)
    assert {:ok, saved} = Mix.Tasks.Sobelow.read_config_file(path)
    assert saved[:ssrf_sinks] == @sinks
    output = capture_io(fn -> Mix.Tasks.Sobelow.run(args ++ ["--no-config"]) end)
    assert [] = output |> Jason.decode!() |> findings_for("SSRF.HTTPClient")
  end

  test "validates configuration without evaluating code" do
    assert CustomSinks.valid?(@sinks)
    assert CustomSinks.valid?([])

    for invalid <- [
          nil,
          %{},
          ["bad"],
          [[module: "MyApp.HTTP"]],
          [Keyword.put(hd(@sinks), :url_arg, 2)],
          [Keyword.put(hd(@sinks), :arity, 0)],
          [Keyword.put(hd(@sinks), :module, {:call, [], []})],
          [Keyword.put(hd(@sinks), :function, :fetch)]
        ] do
      refute CustomSinks.valid?(invalid)
    end
  end
end
