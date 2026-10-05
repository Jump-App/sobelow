defmodule Sobelow.SSRF.CustomSinks do
  @moduledoc false
  @keys [:module, :function, :arity, :url_arg]

  def valid?(sinks) when is_list(sinks), do: Enum.all?(sinks, &valid_sink?/1)
  def valid?(_), do: false

  defp valid_sink?(sink) when is_list(sink) do
    Keyword.keyword?(sink) and Enum.sort(Keyword.keys(sink)) == Enum.sort(@keys) and
      valid_name?(sink[:module], ~r/^[A-Z][A-Za-z0-9_]*(\.[A-Z][A-Za-z0-9_]*)*$/) and
      valid_name?(sink[:function], ~r/^[a-z_][A-Za-z0-9_]*[!?]?$/) and
      is_integer(sink[:arity]) and sink[:arity] in 1..255 and
      is_integer(sink[:url_arg]) and sink[:url_arg] >= 0 and sink[:url_arg] < sink[:arity]
  end

  defp valid_sink?(_), do: false
  defp valid_name?(name, regex), do: is_binary(name) and Regex.match?(regex, name)

  def destination({name, _, args}, source, sinks) when is_list(args) do
    function = function_name(name)

    Enum.find_value(sinks, :error, fn sink ->
      if function == sink[:function] and length(args) == sink[:arity] and
           Sobelow.Lexical.named_call?(source, sink[:module], sink[:arity]) do
        {:ok, Enum.at(args, sink[:url_arg])}
      end
    end)
  end

  def destination(_, _, _), do: :error
  defp function_name({:., _, [_, name]}) when is_atom(name), do: Atom.to_string(name)
  defp function_name(name) when is_atom(name), do: Atom.to_string(name)
  defp function_name(_), do: nil
end
