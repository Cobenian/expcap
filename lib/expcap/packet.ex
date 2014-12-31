defmodule ExPcap.Packet do

  defstruct packet_header:  %ExPcap.PacketHeader{},
            raw_packet_data:    %ExPcap.PacketData{},
            parsed_packet_data: Packet

end
