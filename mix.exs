defmodule ExVault.JwkSet.MixProject do
  use Mix.Project

  @version "0.0.1"

  def project do
    [
      app: :ex_vault_jwk_set,
      version: @version,
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      # hex
      description: "JWK Set with Vault",
      package: package(),

      # ex_doc
      docs: docs()
    ]
  end

  def application do
    [extra_applications: []]
  end

  defp deps do
    [
      {:ex_vault, "~> 0.0.1"},
      {:jose, "~> 1.10"},
      {:credo, "~> 1.1", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0.0", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.22", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/chulkilee/ex_vault_jwk_set",
        "Changelog" => "https://github.com/chulkilee/ex_vault_jwk_set/blob/master/CHANGELOG.md"
      },
      maintainers: ["Chulki Lee"]
    ]
  end

  defp docs do
    [
      name: "ExVault.JwkSet",
      source_ref: "v#{@version}",
      canonical: "https://hexdocs.pm/ex_vault_jwk_set",
      source_url: "https://github.com/chulkilee/ex_vault_jwk_set"
    ]
  end
end
