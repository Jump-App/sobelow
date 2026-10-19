defmodule Sobelow.Crypto.WeakHash do
  @moduledoc """
  # Weak or inappropriate hashing

  MD4, MD5 and SHA-1 are unsuitable when collision resistance is required.
  RIPEMD-160 is reported as a legacy choice, not as a proven collision break.
  Prefer SHA-256 or stronger for security-sensitive digests. Non-security
  checksums and cache keys may legitimately use legacy hashes.

  A fast hash over a password-named value receives medium confidence,
  regardless of algorithm: use a dedicated password KDF such as Argon2id,
  scrypt, bcrypt or appropriately configured PBKDF2 for password storage.
  Naming is a heuristic; preprocessing before a KDF may be intentional.

  Legacy hashes receive medium confidence in controllers and low elsewhere.
  HMAC-MD5 receives low confidence as a legacy construction; HMAC-SHA1 is
  not flagged merely because unkeyed SHA-1 has collision attacks.
  Dynamic algorithm values are not resolved. Calls with literal data,
  inline captures and pipes are included.

  References:
  https://www.rfc-editor.org/rfc/rfc6151
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

      $ mix sobelow -i Crypto.WeakHash
  """
  @uid 38
  @finding_type "Crypto.WeakHash: Weak or Inappropriate Hash"
  @password_names ~w(password passwd pass pw)
  @legacy [:md4, :md5, :sha, :ripemd160]
  @calls [
    {:crypto, :hash, [2]},
    {:crypto, :hash_init, [1]},
    {:erlang, :md5, [1]},
    {:crypto, :mac, [4]},
    {:crypto, :macN, [5]},
    {:crypto, :mac_init, [3]},
    {:crypto, :hmac, [3, 4]}
  ]
  use Sobelow.Finding

  def run(fun, meta_file) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    Enum.each(parse_def(fun), fn {call, reason, confidence} ->
      confidence =
        if confidence == :context,
          do: if(meta_file.controller?, do: :medium, else: :low),
          else: confidence

      Finding.init(@finding_type, meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, {[{call, reason}], params, declaration})
      |> Enum.each(&Print.add_finding/1)
    end)
  end

  # hash(algorithm, data), md5(data), hmac(algorithm, key, data);
  # mac(type, algorithm, key, data). Streaming initializers inspect algorithms only.
  def parse_def(fun) do
    fun
    |> Parse.calls_with_args(@calls)
    |> Enum.flat_map(fn {call, name, args} ->
      case classify(name, args) do
        nil -> []
        {reason, confidence} -> [{call, reason, confidence}]
      end
    end)
  end

  defp classify(:md5, [data]), do: classify(:hash, [:md5, data])

  defp classify(:hash, [algorithm, data]) do
    cond do
      Parse.named_value?(data, @password_names) -> {"fast password hash", :medium}
      algorithm in @legacy -> {algorithm, :context}
      true -> nil
    end
  end

  defp classify(:hash_init, [algorithm]) when algorithm in @legacy, do: {algorithm, :context}
  defp classify(:hmac, [:md5 | _]), do: {"HMAC-MD5", :low}

  defp classify(name, [:hmac, :md5 | _]) when name in [:mac, :macN, :mac_init],
    do: {"HMAC-MD5", :low}

  defp classify(_, _), do: nil
end
