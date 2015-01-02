defimpl String.Chars, for: Protocol.Ipv4 do
  def to_string(ipv4) do
    String.strip("""
    IPv4:
        #{ipv4.header}
        Length:           #{byte_size(ipv4.data)}
        Raw:              #{ExPcap.Binaries.to_raw(ipv4.data)}
    """)
  end
end

defimpl String.Chars, for: Protocol.Ipv4.Header do
  def to_string(ipv4) do
    String.strip("""
        version:          #{ExPcap.Binaries.to_uint4(ipv4.version)}
        ihl:              #{ExPcap.Binaries.to_string(ipv4.ihl)}
        dscp:             #{ExPcap.Binaries.to_string(ipv4.dscp)}
        ecn:              #{ExPcap.Binaries.to_string(ipv4.ecn)}
        totallen:         #{ExPcap.Binaries.to_string(ipv4.totallen)}
        id:               #{ExPcap.Binaries.to_string(ipv4.id)}
        flags:            #{ExPcap.Binaries.to_string(ipv4.flags)}
        fragoffset:       #{ExPcap.Binaries.to_string(ipv4.fragoffset)}
        ttl:              #{ExPcap.Binaries.to_string(ipv4.ttl)}
        protocol:         #{ExPcap.Binaries.to_string(ipv4.protocol)}
        checksum:         #{ExPcap.Binaries.to_string(ipv4.checksum)}
        srcaddr:          #{ExPcap.Binaries.to_string(ipv4.srcaddr)}
        destaddr:         #{ExPcap.Binaries.to_string(ipv4.destaddr)}
        options:          #{ExPcap.Binaries.to_string(ipv4.options)}
        padding:          #{ExPcap.Binaries.to_string(ipv4.padding)}
    """)
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
