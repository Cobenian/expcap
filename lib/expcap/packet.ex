defmodule ExPcap.Packet do

  defstruct packet_header: %ExPcap.PacketHeader{},
            packet_data: %ExPcap.PacketData{}

end
