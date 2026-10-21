defmodule Sobelow.Crypto.WeakRandom do
  @moduledoc """
  # Non-cryptographic randomness in a likely security context

  The default generators behind :rand, :random and Enum's random selection
  functions are unsuitable for secrets. Prefer :crypto.strong_rand_bytes/1
  for tokens, keys and other values that must be unpredictable.

  This check reports medium confidence when a function name, assignment
  target or map/keyword key contains a token, secret, nonce, salt, otp,
  reset or session identifier word. The ambiguous word "code" receives low
  confidence. Ordinary sampling is omitted. Naming is only a heuristic:
  this check neither tracks values between functions nor determines whether
  a random generator has been replaced by a cryptographic plugin.

  https://www.erlang.org/doc/apps/stdlib/rand.html

      $ mix sobelow -i Crypto.WeakRandom
  """
  @uid 40
  @finding_type "Crypto.WeakRandom: Non-Cryptographic Randomness"
  @security_names ~w(token secret nonce salt otp reset session)
  @calls [
    {:rand, :uniform, [0, 1]},
    {:rand, :uniform_s, [1, 2]},
    {:rand, :bytes, [1]},
    {:rand, :bytes_s, [2]},
    {:random, :uniform, [0, 1]},
    {:random, :uniform_s, [1, 2]},
    {[:Enum], :random, [1]},
    {[:Enum], :take_random, [2]},
    {[:Enum], :shuffle, [1]}
  ]
  use Sobelow.Finding

  def run(fun, meta_file) do
    fun |> parse_def() |> Sobelow.Crypto.add_findings(fun, meta_file, @finding_type)
  end

  # Random generators have varied arities; context concerns their result.
  def parse_def(fun) do
    calls = for {call, _, _} <- Parse.calls_with_args(fun, @calls), do: call

    if calls == [] do
      []
    else
      {_, {name, _}} = Parse.get_fun_declaration(fun)
      security = context_calls(fun, name, @security_names, calls)
      code = context_calls(fun, name, ["code"], calls)

      for call <- calls,
          confidence <- [confidence(call, security, code)],
          confidence,
          do: {call, "randomness", confidence}
    end
  end

  # A matching function name puts every call in context.
  defp context_calls(fun, name, names, calls) do
    if Parse.identifier_matches?(name, names),
      do: MapSet.new(calls),
      else: Parse.named_context_calls(fun, names, calls)
  end

  defp confidence(call, security, code) do
    cond do
      MapSet.member?(security, call) -> :medium
      MapSet.member?(code, call) -> :low
      true -> nil
    end
  end
end
