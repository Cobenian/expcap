defimpl String.Chars, for: ExPcap.PacketData do
  @doc """
  Prints the packet data as raw bytes (with the length).
  """
  @spec to_string(ExPcap.PacketData.t) :: String.t
  def to_string(data) do
    String.strip("""
      length:             #{data.data_len}
      raw data:           #{ExPcap.Binaries.to_string(data.data)}
    """)
  end
end

defmodule ExPcap.PacketData do

  @moduledoc """
  This module represents the body of a packet.
  """

  defstruct data_len:   0,
            data:       <<>>

  @type t :: %ExPcap.PacketData{
    data_len: non_neg_integer,
    data: binary
  }

  @doc """
  This function reads the body of a packet reversing the bytes along the way.
  """
  @spec read_reversed(binary, ExPcap.PacketHeader.t) :: ExPcap.PacketData.t
  def read_reversed(data, packet_header) do
    %ExPcap.PacketData{
      data_len: packet_header.incl_len,
      data:     data # |> ExPcap.Binaries.reverse_binary
    }
  end

  @doc """
  This function reads the body of a packet.
  """
  @spec read_forward(binary, ExPcap.PacketHeader.t) :: ExPcap.PacketData.t
  def read_forward(data, packet_header) do
    %ExPcap.PacketData{
      data_len: packet_header.incl_len,
      data:     data
    }
  end

  @doc """
  Reads the packet body from the file.
  """
  @spec from_file(IO.device, ExPcap.GlobalHeader.t, ExPcap.PacketHeader.t) :: ExPcap.PacketData.t
  def from_file(f, global_header, packet_header) do
    data = IO.binread(f, packet_header.incl_len)
    if ExPcap.GlobalHeader.reverse_bytes?(global_header) do
      data |> read_reversed(packet_header)
    else
      data |> read_forward(packet_header)
    end
  end

end
