defprotocol PayloadType do
  @spec payload_parser(any) :: PayloadParser.t
  def payload_parser(this_type)

  @type t :: any
end

defprotocol PayloadParser do
  @spec from_data(binary) :: any
  def from_data(data)

  @type t :: any
end

defimpl String.Chars, for: ExPcap do
  @spec to_string(ExPcap.t) :: String.t
  def to_string(item) do
    """
    PCAP
    ====

    Global Header
    --------------
    #{item.global_header}

    Packets
    -------

    #{Enum.join(Enum.map(item.packets, &String.Chars.to_string/1), "\n\n")}

    """
  end
end

defmodule ExPcap do

  @moduledoc """
  This module represents a pcap file that has been parsed.
  """

  defstruct global_header: %ExPcap.GlobalHeader{},
            packets: [] # %ExPcap.Packet{}

  @type t :: %ExPcap{
    global_header: ExPcap.GlobalHeader.t,
    packets: [ExPcap.Packet.t]
  }

  def parse_packet(packet_data, global_header) do
    parser = PayloadType.payload_parser(global_header)
    parse_packet(parser, packet_data, [])
  end

  def parse_packet(nil, _payload, acc) do
    Enum.reverse acc
  end

  def parse_packet(parser, payload, acc) do
    next_payload = payload.data |> parser.from_data
    next_parser = PayloadType.payload_parser(next_payload)
    parse_packet(next_parser, next_payload, [next_payload | acc])
  end

  def read_packet(f, global_header, packet_header) do
    packet_data = ExPcap.PacketData.from_file(f, global_header, packet_header)
    # packet_data.data |> IO.inspect

    payload = parse_packet(packet_data, global_header)
    # payload |> IO.inspect

    %ExPcap.Packet{
      packet_header: packet_header,
      raw_packet_data: packet_data,
      parsed_packet_data: payload
    }
  end

  def read_packet(f, global_header) do
    packet_header = ExPcap.PacketHeader.from_file(f, global_header)
    case packet_header do
      :eof ->
        :eof
      _ ->
        read_packet(f, global_header, packet_header)
    end
  end

  def read_packets(f, global_header, acc \\ []) do
    next_packet = read_packet(f, global_header)
    case next_packet do
      :eof ->
        acc
      _ ->
        read_packets(f, global_header, [next_packet | acc])
    end

  end

  def read_pcap(f) do
    magic_number = ExPcap.MagicNumber.from_file(f)
    global_header = ExPcap.GlobalHeader.from_file(f, magic_number)

    %ExPcap{
      global_header: global_header,
      packets: f |> read_packets(global_header)
    }
  end

  def from_file(filename) do
    File.open!(filename, fn(file) ->
        read_pcap(file)
    end)
  end

end
