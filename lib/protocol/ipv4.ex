defimpl String.Chars, for: Protocol.Ipv4 do

  @doc """
  Prints an IPv4 packet in a human readable format.
  """
  @spec to_string(Protocol.Ipv4.t) :: String.t
  def to_string(ipv4) do
    """
    IPv4:
        #{ipv4.header}
        Length:           #{byte_size(ipv4.data)}
        Raw:              #{ExPcap.Binaries.to_raw(ipv4.data)}
    """ |> String.strip
  end
end

defimpl String.Chars, for: Protocol.Ipv4.Header do

  @doc """
  Prints an IPv4 header to a human readable format.
  """
  @spec to_string(Protocol.Ipv4.Header.t) :: String.t
  def to_string(ipv4) do
    """
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
    """ |> String.strip
  end
end

defimpl PayloadType, for: Protocol.Ipv4 do
  @doc """
  Returns the parser that will parse the body of this IPv4 packet.
  """
  @spec payload_parser(binary) :: PayloadParser.t
  def payload_parser(data) do
    case data.header.protocol do
      # 06 -> Protocol.Tcp
      <<17>> -> Protocol.Udp
    end
  end
end

defimpl PayloadParser, for: Protocol.Ipv4 do
  @doc """
  Returns the parsed body of the IPv4 packet.
  """
  @spec from_data(binary) :: any
  def from_data(data) do
    data |> Protocol.Ipv4.from_data
  end
end

defmodule Protocol.Ipv4.Header do

  @moduledoc """
  A parsed IPv4 packet header
  """

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

  @type t :: %Protocol.Ipv4.Header{
    version:      bitstring,
    ihl:          bitstring,
    dscp:         bitstring,
    ecn:          bitstring,
    totallen:     non_neg_integer,
    id:           binary,
    flags:        bitstring,
    fragoffset:   bitstring,
    ttl:          binary,
    protocol:     binary,
    checksum:     binary,
    srcaddr:      binary,
    destaddr:     binary,
    options:      binary,
    padding:      binary
  }
end

defmodule Protocol.Ipv4 do

  @moduledoc """
  A parsed IPv4 packet.
  """

  defstruct header: %Protocol.Ipv4.Header{},
            data: <<>>

  @type t :: %Protocol.Ipv4{
    header: Protocol.Ipv4.Header.t,
    data: binary
  }

  @doc """
  Parses an IPv4Header
  """
  @spec header(binary) :: Protocol.Ipv4.Header.t
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

  @doc """
  Parses an IPv4 packet and returns it
  """
  @spec from_data(binary) :: Protocol.Ipv4.t
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
