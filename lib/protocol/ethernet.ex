defmodule Protocol.Ethernet.Header do
  defstruct destmacaddr: <<>>,
            srcmacaddr: <<>>,
            ethertype: <<>>
end

defmodule Protocol.Ethernet do

  defstruct header: %Protocol.Ethernet.Header{},
            data: <<>>

  def header(data) do
    <<
      destmacaddr :: bytes-size(6),
      srcmacaddr  :: bytes-size(6),
      ethertype   :: bytes-size(2),
      payload     :: binary
    >> = data
    %Protocol.Ethernet.Header{
      destmacaddr:  destmacaddr,
      srcmacaddr:   srcmacaddr,
      ethertype:    ethertype
    }
  end

  def from_data(data) do
    <<header :: bytes-size(14), rest :: binary>> = data
    %Protocol.Ethernet{
      header: header(data),
      data: rest
    }
  end
end
