defimpl String.Chars, for: Protocol.Ethernet do
  @doc """
  Prints a human readable ethernet packet to a string.
  """
  @spec to_string(Protocol.Ethernet.t) :: String.t
  def to_string(eth) do
    """
    Ethernet:
        #{eth.header}
        Length:           #{byte_size(eth.data)}
        Raw:              #{ExPcap.Binaries.to_raw(eth.data)}
    """ |> String.trim
  end
end

defimpl String.Chars, for: Protocol.Ethernet.Header do
  @doc """
  Prints a human readable ethernet header as a string.
  """
  @spec to_string(Protocol.Ethernet.Header.t) :: String.t
  def to_string(eth) do
    """
        dest mac addr:    #{ExPcap.Binaries.to_string(eth.destmacaddr)}
        src mac addr:     #{ExPcap.Binaries.to_string(eth.srcmacaddr)}
        ether type:       #{ExPcap.Binaries.to_hex(eth.ethertype)} (#{Protocol.Ethernet.Types.ethernet_type_name(eth.ethertype)})
    """ |> String.trim
  end
end

defimpl PayloadType, for: Protocol.Ethernet do
  @doc """
  Returns the parser that will parse the body of this ethernet packet.
  """
  @spec payload_parser(binary) :: PayloadParser.t
  def payload_parser(data) do
    case data.header.ethertype do
      <<08, 00>> -> Protocol.Ipv4
      # <<134, 221>> -> Protocol.Ipv6
    end
  end
end

defimpl PayloadParser, for: Protocol.Ethernet do
  @doc """
  Returns the parsed payload of this ethernet packet.
  """
  @spec from_data(binary) :: any
  def from_data(data) do
    data |> Protocol.Ethernet.from_data
  end
end

defmodule Protocol.Ethernet.Types do

  @moduledoc """
  This module contains functions related to the payload types that this ethernet
  packet may contain.
  """

  @doc """
  Prints the appropriate human readable ethernet type for the wire format.
  """
  @spec ethernet_type_name(binary) :: String.t
  def ethernet_type_name(eth_type) do
    case eth_type do
      <<08, 00>> -> "IPv4"
      <<134, 221>> -> "IPv6"
      _ -> "unknown"
    end
  end
end

defmodule Protocol.Ethernet.Header do

  @moduledoc """
  A parsed ethernet packet header
  """

  defstruct destmacaddr: <<>>,
            srcmacaddr: <<>>,
            ethertype: <<>>

  @type t :: %Protocol.Ethernet.Header{
    destmacaddr: binary,
    srcmacaddr: binary,
    ethertype: binary
  }
end

defmodule Protocol.Ethernet do

  @moduledoc """
  A parsed ethernet packet
  """

  @bytes_in_header 14

  defstruct header: %Protocol.Ethernet.Header{},
            data: <<>>

  @type t :: %Protocol.Ethernet{
    header: Protocol.Ethernet.Header.t,
    data: binary
  }

  @doc """
  Returns a parsed ethernet header from an ethernet packet.
  """
  @spec header(binary) :: Protocol.Ethernet.Header.t
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

  @doc """
  Returns a parsed ethernet packet.
  """
  @spec from_data(binary) :: Protocol.Ethernet.t
  def from_data(data) do
    <<_header :: bytes-size(@bytes_in_header), rest :: binary>> = data
    %Protocol.Ethernet{
      header: header(data),
      data: rest
    }
  end
end
