defmodule SobelowTest.E2E.DebugErrorsTest do
  use Sobelow.ScanCase, async: false

  test "reports production debug settings for the scanned endpoint" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, OtherWeb.Endpoint, debug_errors: true
    config :basic, BasicWeb.Endpoint, debug_errors: true, code_reloader: true
    """)

    temp_fixture_file("basic", "config/dev.exs", """
    config :basic, BasicWeb.Endpoint, debug_errors: true
    """)

    findings = scan("basic") |> findings_for("Config.DebugErrors")
    assert Enum.frequencies_by(findings, & &1["confidence"]) == %{"high" => 1, "medium" => 1}
    assert Enum.all?(findings, &String.ends_with?(&1["file"], "prod.exs"))
    assert Enum.all?(findings, &(&1["line"] == 2))
  end

  test "later false in prod or runtime suppresses global debug setting" do
    temp_fixture_file("basic", "config/config.exs", """
    config :basic, BasicWeb.Endpoint, debug_errors: true, code_reloader: true
    """)

    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, debug_errors: false
    """)

    temp_fixture_file("basic", "config/runtime.exs", """
    config :basic, BasicWeb.Endpoint, code_reloader: false
    """)

    assert [] = scan("basic") |> findings_for("Config.DebugErrors")
  end

  test "effective setting uses the last value in one file" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, debug_errors: true
    config :basic, BasicWeb.Endpoint, debug_errors: false
    """)

    assert [] = scan("basic") |> findings_for("Config.DebugErrors")
  end

  test "conditional overrides lower confidence" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, debug_errors: true
    if custom_guard?() do
      config :basic, BasicWeb.Endpoint, debug_errors: false
    end
    """)

    assert [%{"confidence" => "low"}] = scan("basic") |> findings_for("Config.DebugErrors")
  end

  test "runtime production guard preserves confidence" do
    temp_fixture_file("basic", "config/runtime.exs", """
    if config_env() == :prod do
      config :basic, BasicWeb.Endpoint, debug_errors: true
    end
    """)

    assert [%{"confidence" => "high", "line" => 2}] =
             scan("basic") |> findings_for("Config.DebugErrors")
  end

  test "runtime development guard does not report" do
    temp_fixture_file("basic", "config/runtime.exs", """
    if config_env() == :dev do
      config :basic, BasicWeb.Endpoint, debug_errors: true
    end
    """)

    assert [] = scan("basic") |> findings_for("Config.DebugErrors")
  end

  test "unguarded Plug.Debugger in endpoint is reported" do
    temp_fixture_file("basic", "lib/basic_web/endpoint.ex", """
    defmodule BasicWeb.Endpoint do
      use Phoenix.Endpoint, otp_app: :basic
      use Plug.Debugger
      if code_reloading?() do
        use Plug.Debugger
      end
    end
    """)

    assert [%{"line" => 3, "confidence" => "medium"}] =
             scan("basic") |> findings_for("Config.DebugErrors")
  end

  test "supports ignore and SARIF registration" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, debug_errors: true
    """)

    assert [_] = scan("basic") |> findings_for("Config.DebugErrors")

    assert [] =
             scan("basic", ignored: ["Config.DebugErrors"]) |> findings_for("Config.DebugErrors")

    {output, _} = scan_io("basic", format: "sarif")
    [run] = Jason.decode!(output)["runs"]
    assert Enum.any?(run["results"], &(&1["ruleId"] == "SBLW035"))
  end
end
