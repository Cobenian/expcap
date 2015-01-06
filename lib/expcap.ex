defprotocol PayloadType do

  @moduledoc """
  This protocol indicates a module that is aware of which parser should be used
  to handle its body.
  """

  @doc """
  This function is passed a packet and it returns the parser that should be used
  to parse its body.
  """
  @spec payload_parser(any) :: PayloadParser.t
  def payload_parser(this_type)

  @type t :: any
end

defprotocol PayloadParser do

  @moduledoc """
  This protocol indicates a module that is aware of how to convert binary data
  to a parsed packet.
  """

  @doc """
  Parses the body of a packet into a new packet (presumably of another protocol)
  For example a UDP packet body may contain a DNS packet. 
  """
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

  @doc """
  Parses the content of the packet according to the parser for this packet type.
  Then it recurses until the packet has been parsed completely.
  It may return something like an ethernet packet that contains an IPv4 packet
  that contains a UDP packet that contains a DNS packet.
  """
  @spec parse_packet(ExPcap.PacketData.t, ExPcap.GlobalHeader.t) :: [ExPcap.Packet.t]
  def parse_packet(packet_data, global_header) do
    parser = PayloadType.payload_parser(global_header)
    parse_packet(parser, packet_data, [])
  end

  @doc """
  Parses the content of the packet according to the parser for this packet type.
  Then it recurses until the packet has been parsed completely.
  It may return something like an ethernet packet that contains an IPv4 packet
  that contains a UDP packet that contains a DNS packet.
  """
  @spec parse_packet(nil, binary, [ExPcap.Packet.t]) :: [ExPcap.Packet.t]
  def parse_packet(nil, _payload, acc) do
    Enum.reverse acc
  end

  @spec parse_packet(ExPcap.Parser.t, binary, [ExPcap.Packet.t]) :: [ExPcap.Packet.t]
  def parse_packet(parser, payload, acc) do
    next_payload = payload.data |> parser.from_data
    next_parser = PayloadType.payload_parser(next_payload)
    parse_packet(next_parser, next_payload, [next_payload | acc])
  end

  @doc """
  Reads a packet from a file. This packet is then parsed and the result is
  returned.
  """
  @spec read_packet(String.t, ExPcap.GlobalHeader.t, ExPcap.PacketHeader.t) :: ExPcap.Packet.t
  def read_packet(f, global_header, packet_header) do
    packet_data = ExPcap.PacketData.from_file(f, global_header, packet_header)

    payload = parse_packet(packet_data, global_header)

    %ExPcap.Packet{
      packet_header: packet_header,
      raw_packet_data: packet_data,
      parsed_packet_data: payload
    }
  end

  @doc """
  Reads a packet from the file and returns it or returns end of file if there
  is no data left to be read.
  """
  @spec read_packet(String.t, ExPcap.GlobalHeader.t) :: :eof | ExPcap.Packet.t
  def read_packet(f, global_header) do
    packet_header = ExPcap.PacketHeader.from_file(f, global_header)
    case packet_header do
      :eof ->
        :eof
      _ ->
        read_packet(f, global_header, packet_header)
    end
  end

  @doc """
  Reads all the packets from a file, parses them and returns a list of the
  parsed packets.
  """
  @spec read_packets(String.t, ExPcap.GlobalHeader.t, list) :: [ExPcap.Packet.t]
  def read_packets(f, global_header, acc \\ []) do
    next_packet = read_packet(f, global_header)
    case next_packet do
      :eof ->
        acc
      _ ->
        read_packets(f, global_header, [next_packet | acc])
    end

  end

  @doc """
  Reads a pcap file and returns the parsed results.
  """
  @spec read_pcap(String.t) :: ExPcap.t
  def read_pcap(f) do
    magic_number = ExPcap.MagicNumber.from_file(f)
    global_header = ExPcap.GlobalHeader.from_file(f, magic_number)

    %ExPcap{
      global_header: global_header,
      packets: f |> read_packets(global_header)
    }
  end

  @doc """
  Reads a file, parses the pcap contents and returns a list of the parsed
  packets.
  """
  @spec from_file(String.t) :: ExPcap.t
  def from_file(filename) do
    File.open!(filename, fn(file) ->
        read_pcap(file)
    end)
  end

end
