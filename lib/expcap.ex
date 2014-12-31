defprotocol Packet do
  def get_header(this)
  def get_payload(this)
end

defprotocol PayloadType do
  def payload_parser(this_type)
end

defprotocol PayloadParser do
  def from_data(data)
end

defimpl PayloadType, for: ExPcap.GlobalHeader do
  def payload_parser(data) do
    Protocol.Ethernet
  end
end

defimpl PayloadType, for: Protocol.Ethernet do
  def payload_parser(data) do
    case data.header.ethertype do
      <<08, 00>> -> Protocol.Ipv4
      # <<134, 221>> -> Protocol.Ipv6
    end
  end
end

defimpl PayloadType, for: Protocol.Ipv4 do
  def payload_parser(data) do
    case data.header.protocol do
      # 06 -> Protocol.Tcp
      <<17>> -> Protocol.Udp
    end
  end
end

defimpl PayloadType, for: Protocol.Udp do
  def payload_parser(data) do
    Protocol.Dns
  end
end

defimpl PayloadParser, for: Protocol.Ethernet do
  def from_data(data) do
    Protocol.Ethernet.from_data data
  end
end

defimpl PayloadParser, for: Protocol.Ipv4 do
  def from_data(data) do
    Protocol.Ipv4.from_data data
  end
end

defimpl PayloadParser, for: Protocol.Udp do
  def from_data(data) do
    Protocol.Udp.from_data data
  end
end

defimpl PayloadParser, for: Protocol.Dns do
  def from_data(data) do
    Protocol.Dns.from_data data
  end
end

defmodule ExPcap do

  defstruct global_header: %ExPcap.GlobalHeader{},
            packets: [] # %ExPcap.Packet{}

  def read_packet(f, global_header, packet_header) do
    packet_data = ExPcap.PacketData.from_file(f, global_header, packet_header)
    # packet_data.data |> IO.inspect

    # todo nest these payloads....

    # ethernet
    parser = PayloadType.payload_parser(global_header)
    payload = packet_data.data |> parser.from_data

    # ip
    parser = PayloadType.payload_parser(payload)
    payload = payload.data |> parser.from_data

    # udp
    parser = PayloadType.payload_parser(payload)
    payload = payload.data |> parser.from_data

    # dns
    parser = PayloadType.payload_parser(payload)
    payload = payload.data |> parser.from_data

    payload |> IO.inspect

    # ethernet = packet_data.data |> Protocol.Ethernet.from_data
    # ethernet |> IO.inspect
    # ipv4 = ethernet.data |> Protocol.Ipv4.from_data
    # ipv4 |> IO.inspect
    # udp = ipv4.data |> Protocol.Udp.from_data
    # udp |> IO.inspect
    # dns = udp.data |> Protocol.Dns.from_data
    # dns |> IO.inspect

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
