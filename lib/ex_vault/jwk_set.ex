defmodule ExVault.JwkSet do
  @moduledoc """
  JWK Set from Vault.

  ### Options

  - `transit_name`
  - `key_name`
  - `client`

  """

  alias ExVault.JwkSet.Key

  @doc false
  defmacro __using__(opts) do
    transit_name = Keyword.fetch!(opts, :transit_name)
    key_name = Keyword.fetch!(opts, :key_name)
    client = Keyword.fetch!(opts, :client)

    quote location: :keep do
      defdelegate to_jwks(keys), to: unquote(__MODULE__)

      def get_available_keys do
        build_client()
        |> unquote(__MODULE__).get_available_keys({transit_name(), key_name()})
      end

      def create_jwt(payload) do
        build_client()
        |> unquote(__MODULE__).create_jwt({transit_name(), key_name()}, payload)
      end

      def create_jwt(payload, key) do
        build_client()
        |> unquote(__MODULE__).create_jwt({transit_name(), key_name(), key}, payload)
      end

      defp build_client, do: val(unquote(client))
      defp transit_name, do: unquote(transit_name)
      defp key_name, do: unquote(key_name)

      defp val({m, f}), do: apply(m, f, [])
      defp val(val), do: val
    end
  end

  def get_available_keys(client, {transit_name, key_name}) do
    case client |> ExVault.Secret.Transit.read_key(transit_name, key_name) do
      {:ok,
       %{
         body: %{
           "data" => %{
             "keys" => vault_keys,
             "min_available_version" => min_available_version,
             "type" => type
           }
         }
       }} ->
        alg =
          case type do
            "rsa-2048" -> "RS256"
            "rsa-3072" -> "RS384"
            "rsa-4096" -> "RS512"
          end

        {:ok,
         vault_keys
         |> Enum.reduce([], fn {version_str, %{"public_key" => public_key_pem}}, acc ->
           {version, ""} = Integer.parse(version_str)

           if version >= min_available_version do
             [
               %Key{
                 alg: alg,
                 kid: Key.version_to_kid(version),
                 version: version,
                 public_key_pem: public_key_pem
               }
               | acc
             ]
           else
             acc
           end
         end)
         |> Enum.sort_by(&Map.fetch!(&1, :version), :desc)}

      {:ok, _} ->
        {:error, "invalid response from vault"}

      {:error, error} ->
        {:error, error}
    end
  end

  def to_jwks(keys) do
    %{keys: Enum.map(keys, &Key.to_jwk_map/1)}
  end

  def create_jwt(client, {transit_name, key_name}, payload) do
    case get_available_keys(client, {transit_name, key_name}) do
      {:ok, [%Key{} = key | _]} -> create_jwt(client, {transit_name, key_name, key}, payload)
      {_, other} -> {:error, other}
    end
  end

  def create_jwt(client, {transit_name, key_name, %Key{} = key}, payload) do
    header = Key.to_jwt_header(key)
    to_sign = encode_component(header) <> "." <> encode_component(payload)

    case sign(client, {transit_name, key_name, key}, to_sign) do
      {:ok, sig} -> {:ok, to_sign <> "." <> sig}
      {:error, error} -> {:error, error}
    end
  end

  def sign(client, {transit_name, key_name, %Key{} = key}, input) do
    %Key{alg: alg, version: version} = key

    {hash_alg, signature_alg} =
      case alg do
        "RS256" -> {"sha2-256", "pkcs1v15"}
        "RS384" -> {"sha2-384", "pkcs1v15"}
        "RS512" -> {"sha2-512", "pkcs1v15"}
      end

    {:ok, %{body: %{"data" => %{"signature" => "vault:v1:" <> encoded}}}} =
      client
      |> ExVault.Secret.Transit.sign_data(transit_name, key_name, %{
        input: Base.encode64(input),
        key_version: version,
        hash_algorithm: hash_alg,
        signature_algorithm: signature_alg
      })

    {:ok, encoded |> Base.decode64!() |> encode()}
  end

  defp encode_component(val), do: val |> Jason.encode!() |> encode()
  defp encode(binary), do: Base.url_encode64(binary, padding: false)
end
