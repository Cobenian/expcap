defimpl String.Chars, for: Protocol.Udp do
  @doc """
  Prints a UDP packet to a human readable string
  """
  @spec to_string(Protocol.Udp.t) :: String.t
  def to_string(udp) do
    String.strip("""
    Udp:
        #{udp.header}
        Length:           #{byte_size(udp.data)}
        Raw:              #{ExPcap.Binaries.to_raw(udp.data)}
    """)
  end
end

defimpl String.Chars, for: Protocol.Udp.Header do
  @doc """
  Prints a UDP packet header to a human readable string
  """
  @spec to_string(Protocol.Udp.t) :: String.t
  def to_string(udp) do
    String.strip("""
        srcport:          #{udp.srcport}
        srcport:          #{udp.destport}
        length:           #{ExPcap.Binaries.to_uint16(udp.length)}
        checksum:         #{ExPcap.Binaries.to_hex(udp.checksum)}
    """)
  end
end

defimpl PayloadType, for: Protocol.Udp do
  @doc """
  Returns the parser that will parse the body of the UDP packet
  """
  @spec payload_parser(binary) :: Protocol.Udp.t
  def payload_parser(_data) do
    Protocol.Dns
  end
end

defimpl PayloadParser, for: Protocol.Udp do
  @doc """
  Returns the parsed body of the UDP packet
  """
  @spec from_data(binary) :: any
  def from_data(data) do
    Protocol.Udp.from_data data
  end
end

defmodule Protocol.Udp.Header do
  @moduledoc """
  A parsed UDP packet header
  """
  defstruct srcport:     <<>>,
            destport:    <<>>,
            length:      <<>>,
            checksum:    <<>>

  @type t :: %Protocol.Udp.Header{
    srcport: non_neg_integer,
    destport: non_neg_integer,
    length: binary,
    checksum: binary
  }
end

defmodule Protocol.Udp do

  @moduledoc """
  A parsed UDP packet
  """

  @bytes_in_header 8

  defstruct header: %Protocol.Udp.Header{},
            data: <<>>

  @type t :: %Protocol.Udp{
    header: Protocol.Udp.Header.t,
    data: binary
  }

  @doc """
  Parses the header of a UDP packet
  """
  @spec header(binary) :: Protocol.Udp.Header.t
  def header(data) do
    <<
      srcport       :: unsigned-integer-size(16),
      destport      :: unsigned-integer-size(16),
      length        :: bytes-size(2),
      checksum      :: bytes-size(2),
      _payload       :: binary
    >> = data
    %Protocol.Udp.Header{
      srcport: srcport,
      destport: destport,
      length: length,
      checksum: checksum
    }
  end

  @doc """
  Returns a parsed UDP packet
  """
  @spec from_data(binary) :: Protocol.Udp.t
  def from_data(data) do
    << _header :: bytes-size(@bytes_in_header), payload :: binary >> = data
    %Protocol.Udp{
      header: header(data),
      data: payload
    }
  end

end
