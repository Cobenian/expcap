defimpl String.Chars, for: ExPcap.Packet do
  @doc """
  Prints a pcap packet in a human friendly manner.
  """
  @spec to_string(ExPcap.Packet.t) :: String.t
  def to_string(packet) do
    String.strip("""
    Packet
    ------
    header:
      #{packet.packet_header}
    parsed:
      #{Enum.join(Enum.map(packet.parsed_packet_data, &String.Chars.to_string/1), "\n  ")}
    raw:
      #{packet.raw_packet_data}
    """)
  end
end

defmodule ExPcap.Packet do

  @moduledoc """
  This module represents a single pcap packet. It contains a header and both raw
  and parsed versions of the body.
  """

  defstruct packet_header:  %ExPcap.PacketHeader{},
            raw_packet_data:    %ExPcap.PacketData{},
            parsed_packet_data: Packet

  @type t :: %ExPcap.Packet{
    packet_header: ExPcap.PacketHeader.t,
    raw_packet_data: ExPcap.PacketData.t,
    parsed_packet_data: Packet
  }

end
