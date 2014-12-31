defmodule Protocol.Dns.Header do
  defstruct id:      <<>>,
            qr:      <<>>,
            opcode:  <<>>,
            aa:      <<>>,
            tc:      <<>>,
            rd:      <<>>,
            ra:      <<>>,
            z:       <<>>,
            rcode:   <<>>,
            qdcnt:   <<>>,
            ancnt:   <<>>,
            nscnt:   <<>>,
            arcnt:   <<>>
end

defmodule Protocol.Dns do

  defstruct header: %Protocol.Dns.Header{},
            data: <<>>

  def header(data) do
    <<
      id      :: bytes-size(2),
      qr      :: bits-size(1),
      opcode  :: bits-size(4),
      aa      :: bits-size(1),
      tc      :: bits-size(1),
      rd      :: bits-size(1),
      ra      :: bits-size(1),
      z       :: bits-size(3),
      rcode   :: bits-size(4),
      qdcnt   :: bytes-size(2),
      ancnt   :: bytes-size(2),
      nscnt   :: bytes-size(2),
      arcnt   :: bytes-size(2),
      payload :: binary
    >> = data
    %Protocol.Dns.Header{
      id:     id,
      qr:     qr,
      opcode: opcode,
      aa:     aa,
      tc:     tc,
      rd:     rd,
      ra:     ra,
      z:      z,
      rcode:  rcode,
      qdcnt:  qdcnt,
      ancnt:  ancnt,
      nscnt:  nscnt,
      arcnt:  arcnt
    }
  end

  def from_data(data) do
    << header :: bytes-size(12), payload :: binary >> = data
    %Protocol.Dns{
      header: header(data),
      data: payload |> String.codepoints
    }
  end

end
