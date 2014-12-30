defmodule ExPcap do

  defstruct global_header: %ExPcap.GlobalHeader{},
            packets: [] # %ExPcap.Packet{}

  def from_file(filename) do
    f = File.open!(filename)

    magic_number = ExPcap.MagicNumber.from_file(f)
    global_header = ExPcap.GlobalHeader.from_file(f, magic_number)

    # todo read packets until end of file
    packet_header = ExPcap.PacketHeader.from_file(f, magic_number)
    packet_data = ExPcap.PacketData.from_file(f, magic_number, packet_header)

    packets = [%ExPcap.Packet{packet_header: packet_header, packet_data: packet_data}]

    pcap = %ExPcap{
      global_header: global_header,
      packets: packets
    }

    File.close(f)

    pcap
  end

end
