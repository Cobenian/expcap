defimpl String.Chars, for: Protocol.Ipv4 do
  def to_string(ipv4) do
    "some ipv4!"
  end
end

defimpl PayloadType, for: Protocol.Ipv4 do
  def payload_parser(data) do
    case data.header.protocol do
      # 06 -> Protocol.Tcp
      <<17>> -> Protocol.Udp
    end
  end
end

defimpl PayloadParser, for: Protocol.Ipv4 do
  def from_data(data) do
    Protocol.Ipv4.from_data data
  end
end

defmodule Protocol.Ipv4.Header do
  defstruct version:      <<>>,
            ihl:          <<>>,
            dscp:         <<>>,
            ecn:          <<>>,
            totallen:     <<>>,
            id:           <<>>,
            flags:        <<>>,
            fragoffset:   <<>>,
            ttl:          <<>>,
            protocol:     <<>>,
            checksum:     <<>>,
            srcaddr:      <<>>,
            destaddr:     <<>>,
            options:      <<>>,
            padding:      <<>>
end

defmodule Protocol.Ipv4 do

  defstruct header: %Protocol.Ipv4.Header{},
            data: <<>>

  def header(data) do
    <<
      version     :: bits-size(4),
      ihl         :: bits-size(4),
      dscp        :: bits-size(6),
      ecn         :: bits-size(2),
      totallen    :: unsigned-integer-size(16),
      id          :: bytes-size(2),
      flags       :: bits-size(3),
      fragoffset  :: bits-size(13),
      ttl         :: bytes-size(1),
      protocol    :: bytes-size(1),
      checksum    :: bytes-size(2),
      srcaddr     :: bytes-size(4),
      destaddr    :: bytes-size(4),
      options     :: bytes-size(3),
      padding     :: bytes-size(1),
      _payload    :: binary
    >> = data
    %Protocol.Ipv4.Header{
      version: version,
      ihl: ihl,
      dscp: dscp,
      ecn: ecn,
      totallen: totallen,
      id: id,
      flags: flags,
      fragoffset: fragoffset,
      ttl: ttl,
      protocol: protocol, # determines the payload content type (http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
      checksum: checksum,
      srcaddr: srcaddr,
      destaddr: destaddr,
      options: options,
      padding: padding
    }
  end

  def from_data(data) do
    ipv4_header = header(data)
    # header size can be between 20 and 60 (see ihl value in the header...)
    header_size = ExPcap.Binaries.to_uint4(ipv4_header.ihl) * 4
    << _header :: bytes-size(header_size), payload :: binary >> = data
    %Protocol.Ipv4{
      header: ipv4_header,
      data: payload
    }
  end

end
