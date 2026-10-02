defmodule Sobelow.Config.DebugErrors do
  @moduledoc """
  # Debug errors and code reloading in production

  Reports `debug_errors: true` and `code_reloader: true` in production
  endpoint configuration. The former exposes exception details and source
  code to clients; the latter enables development-only code reloading.
  Also reports unguarded `use Plug.Debugger` in an endpoint or router.

  Settings in `dev.exs` and `test.exs` are excluded. A later `false` in
  production or runtime config suppresses an earlier `true` for the same
  endpoint. Conditional and dynamic later settings lower confidence when
  they may override a known unsafe value. Static analysis cannot resolve
  arbitrary helper functions or imported configuration files.

  Ignore this check with:

      $ mix sobelow -i Config.DebugErrors
  """
  @uid 35
  @finding_type "Config.DebugErrors: Debug Error Pages or Code Reloading Enabled"
  @settings [debug_errors: :high, code_reloader: :medium]
  @production_files ["config.exs", "prod.exs", "runtime.exs"]

  use Sobelow.Finding
  alias Sobelow.Config

  def run(dir_path, configs, endpoints, routers) do
    files = Enum.filter(@production_files, &(&1 in configs))

    endpoints
    |> Enum.flat_map(&endpoint_modules/1)
    |> Enum.uniq()
    |> Enum.each(fn module ->
      Enum.each(@settings, fn {key, confidence} ->
        files
        |> Enum.reduce(nil, fn file, state ->
          setting(Path.join(dir_path, file), module, key, confidence, state)
        end)
        |> maybe_add_finding()
      end)
    end)

    Enum.each(Enum.uniq(endpoints ++ routers), fn path ->
      path
      |> Parse.ast()
      |> debugger_calls()
      |> Enum.each(&add_finding(path, &1, :medium))
    end)
  end

  @doc false
  def debugger_calls(ast), do: debugger_calls(ast, false)

  defp debugger_calls({:use, _, [{:__aliases__, _, [:Plug, :Debugger]} | _]} = call, false),
    do: [call]

  defp debugger_calls({kind, _, args}, _guarded?)
       when kind in [:if, :unless, :case, :cond, :with] and is_list(args),
       do: Enum.flat_map(args, &debugger_calls(&1, true))

  defp debugger_calls({_, _, args}, guarded?) when is_list(args),
    do: Enum.flat_map(args, &debugger_calls(&1, guarded?))

  defp debugger_calls(nodes, guarded?) when is_list(nodes),
    do: Enum.flat_map(nodes, &debugger_calls(&1, guarded?))

  defp debugger_calls({_key, value}, guarded?), do: debugger_calls(value, guarded?)
  defp debugger_calls(_, _), do: []

  defp endpoint_modules(path) do
    path
    |> Parse.ast()
    |> Parse.get_funs_of_type(:defmodule)
    |> Enum.flat_map(fn
      {:defmodule, _, [{:__aliases__, _, module} | _]} ->
        if List.last(module) == :Endpoint, do: [module], else: []

      _ ->
        []
    end)
  end

  defp setting(path, module, key, confidence, previous) do
    case Config.effective_endpoint_config(key, path, module) do
      :error ->
        previous

      {:ok, true} ->
        path |> literal_setting(module, key) |> finding_state(path, confidence)

      {:ok, false} ->
        nil

      {:ok, _unknown} ->
        case Config.get_endpoint_configs(key, path, module) do
          [{call, ^key, value} | earlier] ->
            case guard_for_call(Parse.ast(path), call, :unconditional) do
              :nonprod -> previous
              :prod when value == true -> {path, call, confidence}
              :prod when value == false -> nil
              _ when value == true -> {path, call, :low}
              _ -> downgrade(previous || earlier_true(path, key, earlier))
            end

          [] ->
            downgrade(previous)
        end
    end
  end

  defp earlier_true(path, key, records) do
    Enum.find_value(records, fn
      {call, ^key, true} -> {path, call, :low}
      _ -> nil
    end)
  end

  defp literal_setting(path, module, key) do
    Config.get_endpoint_configs(key, path, module)
    |> Enum.find_value(fn
      {call, ^key, true} -> call
      _ -> nil
    end)
  end

  defp guard_for_call(node, target, guard) when node == target, do: guard

  defp guard_for_call({:if, _, [condition, clauses]}, target, guard) when is_list(clauses) do
    {then_guard, else_guard} = branch_guards(condition)

    guard_for_call(Keyword.get(clauses, :do), target, combine_guard(guard, then_guard)) ||
      guard_for_call(Keyword.get(clauses, :else), target, combine_guard(guard, else_guard))
  end

  defp guard_for_call({kind, _, args}, target, guard) when is_list(args) do
    nested_guard =
      if kind in [:unless, :case, :cond, :for, :with, :try, :fn, :def, :defp],
        do: combine_guard(guard, :conditional),
        else: guard

    guard_for_call(args, target, nested_guard)
  end

  defp guard_for_call(nodes, target, guard) when is_list(nodes),
    do: Enum.find_value(nodes, &guard_for_call(&1, target, guard))

  defp guard_for_call({_key, value}, target, guard), do: guard_for_call(value, target, guard)
  defp guard_for_call(_, _, _), do: nil

  defp branch_guards({operator, _, [environment, value]})
       when operator in [:==, :===, :!=, :!==] and is_atom(value) do
    if environment_call?(environment) and value in [:prod, :dev, :test] do
      case {operator in [:==, :===], value} do
        {true, :prod} -> {:prod, :nonprod}
        {false, :prod} -> {:nonprod, :prod}
        {true, _} -> {:nonprod, :conditional}
        {false, _} -> {:conditional, :nonprod}
      end
    else
      {:conditional, :conditional}
    end
  end

  defp branch_guards(_), do: {:conditional, :conditional}

  defp environment_call?({:config_env, _, []}), do: true
  defp environment_call?({{:., _, [{:__aliases__, _, [:Mix]}, :env]}, _, []}), do: true
  defp environment_call?(_), do: false

  defp combine_guard(:nonprod, _), do: :nonprod
  defp combine_guard(_, :nonprod), do: :nonprod
  defp combine_guard(:conditional, _), do: :conditional
  defp combine_guard(_, :conditional), do: :conditional
  defp combine_guard(:prod, _), do: :prod
  defp combine_guard(_, :prod), do: :prod
  defp combine_guard(_, _), do: :unconditional

  defp finding_state(nil, _path, _confidence), do: nil
  defp finding_state(call, path, confidence), do: {path, call, confidence}
  defp downgrade({path, call, _confidence}), do: {path, call, :low}
  defp downgrade(nil), do: nil

  defp maybe_add_finding(nil), do: :ok
  defp maybe_add_finding({path, call, confidence}), do: add_finding(path, call, confidence)

  defp add_finding(path, call, confidence) do
    finding =
      Finding.init(@finding_type, Utils.normalize_path(path), confidence)
      |> Map.merge(%{
        vuln_source: :highlight_all,
        vuln_line_no: Parse.get_fun_line(call),
        vuln_col_no: Parse.get_fun_column(call),
        fun_source: call
      })

    Print.add_finding(finding)
  end
end
