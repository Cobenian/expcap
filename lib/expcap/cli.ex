defmodule ExPcap.CLI do
  @moduledoc """
  Prints the contents of a PCAP file to stdout.

  The file may be specified with the --file or -f flag.

  If no flags are passed (or --help or -h) then the help is printed.
  """

  @doc """
  The entry point, a.k.a. the main function.
  """
  @spec main(list) :: nil
  def main(argv) do
    argv |> run
  end

  @doc """
  Parses the arguments and then either prints the contents of the PCAP file or
  prints the help message.
  """
  @spec run(list) :: nil
  def run(argv) do
    argv |> parse_args |> process |> IO.puts
  end

  @doc """
  Parses the arguments which may be either:
  --help, -h                :help
  --file, -f <name>         [file: name]
  """
  # @spec parse_args(list) :: atom | [atom String.t]
  def parse_args(argv) do
    parse = argv |> OptionParser.parse(
      switches: [help: :boolean, file: :string],
      aliases: [h: :help, f: :file]
    )
    case parse do
      { [ help: true ], _, _ } -> :help
      { [ file: name ], _, _ } -> [file: name]
      _ -> :help
    end
  end

  @doc """
  Prints the help message.
  """
  @spec process(:help) :: String.t
  def process(:help) do
    """
      --file, -f <file>       The PCAP file to use
      --help, -h              Print this message
    """
  end

  @doc """
  Prints the contents of the PCAP file in a somewhat human readable form.
  """
  @spec process([:file | String.t]) :: String.t
  def process([file: file]) do
    file |> ExPcap.from_file |> String.Chars.to_string
  end
end
