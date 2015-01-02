defimpl String.Chars, for: Protocol.Ethernet do
  def to_string(eth) do
    String.strip("""
    Ethernet:
        #{eth.header}
        Length:           #{byte_size(eth.data)}
    """)
  end
end

defimpl String.Chars, for: Protocol.Ethernet.Header do
  def to_string(eth) do
    String.strip("""
        dest mac addr:    #{ExPcap.Binaries.to_string(eth.destmacaddr)}
        src mac addr:     #{ExPcap.Binaries.to_string(eth.srcmacaddr)}
        ether type:       #{ExPcap.Binaries.to_hex(eth.ethertype)} (#{Ethernet.Types.ethernet_type_name(eth.ethertype)})
    """)
  end
end

defimpl PayloadType, for: Protocol.Ethernet do
  def payload_parser(data) do
    case data.header.ethertype do
      <<08, 00>> -> Protocol.Ipv4
      # <<134, 221>> -> Protocol.Ipv6
    end
  end
end

defimpl PayloadParser, for: Protocol.Ethernet do
  def from_data(data) do
    Protocol.Ethernet.from_data data
  end
end

defmodule Ethernet.Types do
    def ethernet_type_name(eth_type) do
      case eth_type do
        <<08, 00>> -> "IPv4"
        <<134, 221>> -> "IPv6"
        _ -> "unknown"
      end
    end
end

defmodule Protocol.Ethernet.Header do
  defstruct destmacaddr: <<>>,
            srcmacaddr: <<>>,
            ethertype: <<>>
end

defmodule Protocol.Ethernet do

  @bytes_in_header 14

  defstruct header: %Protocol.Ethernet.Header{},
            data: <<>>

  def header(data) do
    <<
      destmacaddr :: bytes-size(6),
      srcmacaddr  :: bytes-size(6),
      ethertype   :: bytes-size(2), # determines the payload type (http://en.wikipedia.org/wiki/EtherType)
      _payload    :: binary
    >> = data
    %Protocol.Ethernet.Header{
      destmacaddr:  destmacaddr,
      srcmacaddr:   srcmacaddr,
      ethertype:    ethertype
    }
  end

  def from_data(data) do
    <<_header :: bytes-size(@bytes_in_header), rest :: binary>> = data
    %Protocol.Ethernet{
      header: header(data),
      data: rest
    }
  end
end
