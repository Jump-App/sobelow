defmodule SobelowTest.E2E.DestinationsTest do
  use Sobelow.ScanCase, async: false

  @opts [router: :none, ignored: ["Config", "Vuln"]]

  test "reports destinations at the correct confidence and source location" do
    report = scan("destinations", @opts)

    assert Enum.frequencies_by(findings_for(report, "SSRF.HTTPClient"), & &1["confidence"]) ==
             %{"high" => 4, "medium" => 1, "low" => 1}

    assert Enum.frequencies_by(findings_for(report, "Misc.OpenRedirect"), & &1["confidence"]) ==
             %{"high" => 2, "medium" => 1, "low" => 1}

    assert Enum.any?(findings_for(report, "SSRF.HTTPClient"), fn finding ->
             finding["line"] == 5 and finding["variable"] == "url" and
               String.ends_with?(finding["file"], "page_controller.ex")
           end)

    assert Enum.any?(findings_for(report, "Misc.OpenRedirect"), &(&1["line"] == 8))
  end

  test "respects category and individual ignores" do
    assert scan("destinations", Keyword.put(@opts, :ignored, ["Config", "Vuln", "SSRF"]))
           |> findings_for("SSRF.HTTPClient") == []

    assert scan(
             "destinations",
             Keyword.put(@opts, :ignored, [
               "Config",
               "Vuln",
               "SSRF.HTTPClient",
               "Misc.OpenRedirect"
             ])
           )
           |> findings() == []
  end

  test "respects function skips and confidence thresholds" do
    report = scan("destinations", @opts ++ [skip: true, threshold: :high])
    assert length(findings_for(report, "SSRF.HTTPClient")) == 3
    assert length(findings_for(report, "Misc.OpenRedirect")) == 1
  end

  test "SARIF registers and references both rules" do
    report = scan("destinations", @opts ++ [format: "sarif"])
    [run] = report["runs"]

    assert Enum.frequencies_by(run["results"], & &1["ruleId"]) == %{
             "SBLW032" => 6,
             "SBLW033" => 4
           }

    rules = run["tool"]["driver"]["rules"]
    assert Enum.any?(rules, &(&1["id"] == "SBLW032" and &1["name"] == "SSRF.HTTPClient"))
    assert Enum.any?(rules, &(&1["id"] == "SBLW033" and &1["name"] == "Misc.OpenRedirect"))
  end

  for format <- ["txt", "compact", "flycheck"] do
    test "renders both findings as #{format}" do
      {stdout, _} = scan_io("destinations", @opts ++ [format: unquote(format)])
      assert stdout =~ "SSRF.HTTPClient"
      assert stdout =~ "Misc.OpenRedirect"
    end
  end
end
