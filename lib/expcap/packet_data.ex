defmodule ExPcap.PacketData do

  defstruct data_len:   0,
            data:       <<>>

  def read_reversed(data, packet_header) do
    %ExPcap.PacketData{
      data_len: packet_header.incl_len,
      data:     data |> ExPcap.Binaries.reverse_binary |> String.codepoints
    }
  end

  def read_forward(data, packet_header) do
    %ExPcap.PacketData{
      data_len: packet_header.incl_len,
      data:     data |> String.codepoints
    }
  end

  def from_file(f, magic_number, packet_header) do
    data = IO.binread(f, packet_header.incl_len)
    if magic_number.reverse_bytes do
      data |> read_reversed(packet_header)
    else
      data |> read_forward(packet_header)
    end
  end

end
