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
