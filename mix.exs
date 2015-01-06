defmodule ExPcap.Mixfile do
  use Mix.Project

  def project do
    [app: :expcap,
     version: "0.1.0",
     elixir: "~> 1.0",
     name: "expcap",
     source_url: "https://github.com/cobenian/expcap",
     deps: deps,
     escript: escript]
  end

  def escript do
    [main_module: ExPcap.CLI]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type `mix help deps` for more examples and options
  defp deps do
    [{:timex, "~> 0.13.2"},
     {:earmark, "~> 0.1", only: :dev},
     {:ex_doc, "~> 0.6", only: :dev }]
  end
end
