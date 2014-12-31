defimpl String.Chars, for: ExPcap.Packet do
  def to_string(packet) do
    String.strip("""
    Packet
    ------
    header:
      #{packet.packet_header}
    parsed:
      #{is_list(packet.parsed_packet_data)}
    raw:
      #{packet.raw_packet_data}
    """)
  end
end

defmodule ExPcap.Packet do

  defstruct packet_header:  %ExPcap.PacketHeader{},
            raw_packet_data:    %ExPcap.PacketData{},
            parsed_packet_data: Packet

end
