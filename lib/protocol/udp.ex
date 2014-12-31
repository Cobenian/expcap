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
