defmodule Sobelow.Crypto do
  @moduledoc """
  # Cryptography

  Checks algorithm choices and likely security uses of non-cryptographic
  randomness. These checks do not prove that a cryptographic construction
  is secure or that a value is secret.

      $ mix sobelow -d Crypto.WeakHash
      $ mix sobelow -d Crypto.WeakCipher
      $ mix sobelow -d Crypto.WeakRandom

  Ignore the category with:

      $ mix sobelow -i Crypto
  """
  @submodules [Sobelow.Crypto.WeakHash, Sobelow.Crypto.WeakCipher, Sobelow.Crypto.WeakRandom]
  use Sobelow.FindingType

  def get_vulns(fun, meta_file, _web_root, skip_mods \\ []) do
    __MODULE__
    |> Sobelow.allowed_checks(@submodules, skip_mods)
    |> Enum.each(& &1.run(fun, meta_file))
  end

  def details, do: @moduledoc
end
