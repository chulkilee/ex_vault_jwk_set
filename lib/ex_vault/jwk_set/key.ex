defmodule ExVault.JwkSet.Key do
  @moduledoc """
  Vault key entry.fun()
  """

  @type t :: %__MODULE__{
          alg: String.t(),
          kid: String.t(),
          public_key_pem: String.t(),
          version: integer
        }

  defstruct [:alg, :kid, :public_key_pem, :version]

  @kid_prefix "v:"

  @doc """
  Returns `kid` for given Vault key version.

  ### Examples

      iex> ExVault.JwkSet.Key.version_to_kid(1)
      "v:1"

  """
  def version_to_kid(version), do: @kid_prefix <> Integer.to_string(version)

  @doc """
  Returns Vault key version for given`kid`.

  ### Examples

      iex> ExVault.JwkSet.Key.kid_to_version("v:1")
      {:ok, 1}

      iex> ExVault.JwkSet.Key.kid_to_version("bar:1")
      {:error, :invalid_kid}

  """
  def kid_to_version(kid) do
    with @kid_prefix <> version_str <- kid,
         {version, ""} <- Integer.parse(version_str) do
      {:ok, version}
    else
      _ -> {:error, :invalid_kid}
    end
  end

  @doc """
  Returns JWK in a map.

  ### Examples

      iex> ExVault.JwkSet.Key.to_jwk_map(%ExVault.JwkSet.Key{
      ...>      version: 1,
      ...>      public_key_pem: \"\"\"
      ...>      -----BEGIN PUBLIC KEY-----
      ...>      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
      ...>      vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
      ...>      aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
      ...>      tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
      ...>      e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
      ...>      V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
      ...>      MwIDAQAB
      ...>      -----END PUBLIC KEY-----
      ...>      \"\"\"
      ...>    })
      %{
        "e" => "AQAB",
        "kid" => "v:1",
        "kty" => "RSA",
        "n" =>
          "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw"
      }
  """
  def to_jwk_map(%__MODULE__{version: version} = key) do
    {_, jwk_map} =
      key
      |> to_jose_jwk()
      |> JOSE.JWK.to_map()

    jwk_map |> Map.put("kid", version_to_kid(version))
  end

  @doc """
  Returns `JOSE.JWK`.

  ### Examples

      iex> ExVault.JwkSet.Key.to_jose_jwk(%ExVault.JwkSet.Key{
      ...>      alg: "RS256",
      ...>      version: 1,
      ...>      public_key_pem: \"\"\"
      ...>      -----BEGIN PUBLIC KEY-----
      ...>      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
      ...>      vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
      ...>      aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
      ...>      tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
      ...>      e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
      ...>      V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
      ...>      MwIDAQAB
      ...>      -----END PUBLIC KEY-----
      ...>      \"\"\"
      ...>    })
      %JOSE.JWK{
        fields: %{},
        keys: :undefined,
        kty:
          {:jose_jwk_kty_rsa,
          {:RSAPublicKey,
          20101790993208644745807976729182597941929355612162354360099435269825087678371993244844234893013558555686015831335725398637423399304205115261083991022355813201997154499053064318477614909646953959855907663206692927300016800053636628573275271404089122405985685162285559162700174320318326821436949689956974724260182115938767812249391575639780973664572557729842107578524708525191776956150194917696738395922018602710772475751229671360413648976296942707837850780316509559008920087532825564663621482064344153450826739561548502662708814824842358869389530164169290288156380027449103702069177196558531588515097343487007237750067,
            65537}}
      }
  """
  def to_jose_jwk(%__MODULE__{public_key_pem: public_key_pem}),
    do: public_key_pem |> JOSE.JWK.from_pem()

  @doc """
  Returns JWT header.

  ### Examples

      iex> ExVault.JwkSet.Key.to_jwt_header(%ExVault.JwkSet.Key{
      ...>      alg: "RS256",
      ...>      kid: "foo",
      ...>      version: 1,
      ...>      public_key_pem: \"\"\"
      ...>      -----BEGIN PUBLIC KEY-----
      ...>      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
      ...>      vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
      ...>      aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
      ...>      tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
      ...>      e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
      ...>      V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
      ...>      MwIDAQAB
      ...>      -----END PUBLIC KEY-----
      ...>      \"\"\"
      ...>    })
      %{alg: "RS256", kid: "foo", typ: "JWT"}
  """
  def to_jwt_header(%__MODULE__{alg: alg, kid: kid}) do
    %{alg: alg, kid: kid, typ: "JWT"}
  end
end
