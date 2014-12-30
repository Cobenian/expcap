defmodule ExPcap.PacketData do

  defstruct data_len:   0,
            data:       <<>>

  def from_file(f, packet_header) do
    data = IO.binread(f, packet_header.incl_len)
    %ExPcap.PacketData{
      data_len: packet_header.incl_len,
      data:     data |> ExPcap.Binaries.reverse_binary |> String.codepoints
    }
  end

end
