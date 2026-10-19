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
    {params, declaration} = Parse.get_fun_declaration(fun)

    Enum.each(parse_def(fun), fn {call, confidence} ->
      Finding.init(@finding_type, meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, {[{call, "randomness"}], params, declaration})
      |> Enum.each(&Print.add_finding/1)
    end)
  end

  # Random generators have varied arities; context concerns their result.
  def parse_def(fun) do
    {_, {name, _}} = Parse.get_fun_declaration(fun)
    security_nodes = Parse.named_context_nodes(fun, @security_names)
    code_nodes = Parse.named_context_nodes(fun, ["code"])

    fun
    |> Parse.calls_with_args(@calls)
    |> Enum.flat_map(fn {call, _, _} ->
      cond do
        Parse.identifier_matches?(name, @security_names) or MapSet.member?(security_nodes, call) ->
          [{call, :medium}]

        Parse.identifier_matches?(name, ["code"]) or MapSet.member?(code_nodes, call) ->
          [{call, :low}]

        true ->
          []
      end
    end)
  end
end
