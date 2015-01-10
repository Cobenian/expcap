defmodule ExPcap.Mixfile do
  use Mix.Project

  def project do
    [app: :expcap,
     version: "0.1.1",
     elixir: "~> 1.0",
     name: "expcap",
     source_url: "https://github.com/cobenian/expcap",
     description: description,
     package: package,
     deps: deps,
     docs: docs,
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

  defp docs do
    [{:main, "ExPcap"}]
  end

  defp description do
    """
    A PCAP library written in Elixir. This does not wrap a C or Erlang PCAP library,
    rather it attempts to be an idiomatic Elixir library.

    This library parses pcap files, however it does not yet support most protocols
    that can be contained within a pcap file. The only supported protocols at the
    moment are:

    * Ethernet

    * IPv4

    * UDP

    * DNS

    """
  end

  defp package do
    [# These are the default files included in the package
    files: ["lib", "priv", "mix.exs", "README*", "readme*", "LICENSE*", "license*"],
    contributors: ["Bryan Weber"],
    licenses: ["Apache 2.0"],
    links: %{"GitHub" => "https://github.com/cobenian/expcap",
    "Docs" => "http://cobenian.github.io/expcap/"}]
  end
end
