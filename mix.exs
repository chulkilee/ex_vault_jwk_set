defmodule ExVault.JwkSet.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_vault_jwk_set,
      version: "0.0.1-dev",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [extra_applications: []]
  end

  defp deps do
    []
  end
end
