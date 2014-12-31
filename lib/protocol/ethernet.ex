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
