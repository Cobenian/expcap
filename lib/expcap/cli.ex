defmodule ExPcap.CLI do
  @moduledoc """

  """
  def main(argv) do
    run(argv)
  end

  def run(argv) do
    argv |> parse_args |> process
  end

  def parse_args(argv) do
    parse = OptionParser.parse(argv,
      switches: [help: :boolean, file: :string],
      aliases: [h: :help, f: :file]
    )
    case parse do
      { [ help: true ], _, _ } -> :help
      { [ file: name ], _, _ } -> [file: name]
      _ -> :help
    end
  end

  def process(:help) do
    IO.puts """
      --file, -f <file>       The PCAP file to use
      --help, -h              Print this message
    """
    System.halt(0)
  end

  def process([file: file]) do
    file |> ExPcap.from_file |> String.Chars.to_string |> IO.puts
  end
end
