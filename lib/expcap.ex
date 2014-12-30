defmodule ExPcap do

  defstruct global_header: %ExPcap.GlobalHeader{},
            packets: [] # %ExPcap.Packet{}

  def read_pcap(f) do
    magic_number = ExPcap.MagicNumber.from_file(f)
    global_header = ExPcap.GlobalHeader.from_file(f, magic_number)

    # todo read packets until end of file
    packet_header = ExPcap.PacketHeader.from_file(f, global_header)
    packet_data = ExPcap.PacketData.from_file(f, global_header, packet_header)

    packets = [%ExPcap.Packet{packet_header: packet_header, packet_data: packet_data}]

    %ExPcap{
      global_header: global_header,
      packets: packets
    }
  end

  def from_file(filename) do
    File.open!(filename, fn(file) ->
        read_pcap(file)
    end)
  end

end
