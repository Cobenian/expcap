defmodule ExPcap do

  defstruct global_header: %ExPcap.GlobalHeader{},
            packets: [] # %ExPcap.Packet{}

  def read_packets(f, global_header, acc \\ []) do
    packet_header = ExPcap.PacketHeader.from_file(f, global_header)
    case packet_header do
      :eof ->
        acc
      _ ->
        packet_data = ExPcap.PacketData.from_file(f, global_header, packet_header)
        # packet_data.data |> IO.inspect
        # global_header |> IO.inspect
        # packet_header |> IO.inspect
        # IO.puts "length is #{byte_size(packet_data.data)}"
        # packet_data.data |> IO.inspect
        # ethernet = packet_data.data |> Protocol.Ethernet.header
        ethernet = packet_data.data |> Protocol.Ethernet.from_data
        # ethernet |> IO.inspect
        ipv4 = ethernet.data |> Protocol.Ipv4.from_data
        # ipv4 |> IO.inspect
        udp = ipv4.data |> Protocol.Udp.from_data
        # udp |> IO.inspect
        dns = udp.data |> Protocol.Dns.from_data
        dns |> IO.inspect
        # packet_data.data |> Protocol.Ipv4.header |> IO.inspect
        # packet_data.data |> Protocol.Dns.header |> IO.inspect
        # packet_data.data |> Protocol.Udp.header |> IO.inspect
        new_pcap = %ExPcap.Packet{packet_header: packet_header, packet_data: packet_data}
        read_packets(f, global_header, [new_pcap | acc])
    end

  end

  def read_pcap(f) do
    magic_number = ExPcap.MagicNumber.from_file(f)
    global_header = ExPcap.GlobalHeader.from_file(f, magic_number)

    # # todo stream of packets instead of eager fetching
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
