defimpl String.Chars, for: Protocol.Udp do
  def to_string(udp) do
    String.strip("""
    Udp:
        #{udp.header}
        Length:           #{byte_size(udp.data)}
    """)
  end
end

defimpl String.Chars, for: Protocol.Udp.Header do
  def to_string(udp) do
    String.strip("""
        srcport:          #{udp.srcport}
        srcport:          #{udp.destport}
        length:           #{ExPcap.Binaries.to_uint16(udp.length)}
        checksum:         #{ExPcap.Binaries.to_string(udp.checksum)}
    """)
  end
end

defimpl PayloadType, for: Protocol.Udp do
  def payload_parser(_data) do
    Protocol.Dns
  end
end

defimpl PayloadParser, for: Protocol.Udp do
  def from_data(data) do
    Protocol.Udp.from_data data
  end
end

defmodule Protocol.Udp.Header do
  defstruct srcport:     <<>>,
            destport:    <<>>,
            length:      <<>>,
            checksum:    <<>>
end

defmodule Protocol.Udp do

  @bytes_in_header 8

  defstruct header: %Protocol.Udp.Header{},
            data: <<>>

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

  def from_data(data) do
    << _header :: bytes-size(@bytes_in_header), payload :: binary >> = data
    %Protocol.Udp{
      header: header(data),
      data: payload
    }
  end

end
