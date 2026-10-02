defmodule SobelowTest.Config.DebugErrorsTest do
  use ExUnit.Case, async: true

  alias Sobelow.Config.DebugErrors

  test "finds unguarded Plug.Debugger but skips conditional use" do
    ast =
      Code.string_to_quoted!("""
      defmodule Web.Endpoint do
        use Plug.Debugger
        if code_reloading?() do
          use Plug.Debugger
        end
      end
      """)

    assert [call] = DebugErrors.debugger_calls(ast)
    assert Sobelow.Parse.get_fun_line(call) == 2
  end
end
