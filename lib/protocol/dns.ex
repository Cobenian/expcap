defimpl String.Chars, for: Protocol.Dns do
  def to_string(dns) do
    String.strip("""
    DNS:
        #{dns.header}
        Length:           #{byte_size(dns.data)}
        Raw:              #{ExPcap.Binaries.to_raw(dns.data)}
    """)
  end
end

defimpl String.Chars, for: Protocol.Dns.Header do
  def to_string(dns) do
    String.strip("""
        id:               #{ExPcap.Binaries.to_string(dns.id)}
        qr:               #{ExPcap.Binaries.to_string(dns.qr)}
        opcode:           #{ExPcap.Binaries.to_string(dns.opcode)}
        aa:               #{ExPcap.Binaries.to_string(dns.aa)}
        tc:               #{ExPcap.Binaries.to_string(dns.tc)}
        rd:               #{ExPcap.Binaries.to_string(dns.rd)}
        ra:               #{ExPcap.Binaries.to_string(dns.ra)}
        z:                #{ExPcap.Binaries.to_string(dns.z)}
        rcode:            #{ExPcap.Binaries.to_string(dns.rcode)}
        qdcnt:            #{ExPcap.Binaries.to_string(dns.qdcnt)}
        ancnt:            #{ExPcap.Binaries.to_string(dns.ancnt)}
        nscnt:            #{ExPcap.Binaries.to_string(dns.nscnt)}
        arcnt:            #{ExPcap.Binaries.to_string(dns.arcnt)}
    """)
  end
end

defimpl PayloadType, for: Protocol.Dns do
  def payload_parser(_data) do
    nil
  end
end

defimpl PayloadParser, for: Protocol.Dns do
  def from_data(data) do
    Protocol.Dns.from_data data
  end
end

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

  @bytes_in_header 12

  defstruct header: %Protocol.Dns.Header{},
            data: <<>>

  def header(data) do
    <<
      id        :: bytes-size(2),
      qr        :: bits-size(1),
      opcode    :: bits-size(4),
      aa        :: bits-size(1),
      tc        :: bits-size(1),
      rd        :: bits-size(1),
      ra        :: bits-size(1),
      z         :: bits-size(3),
      rcode     :: bits-size(4),
      qdcnt     :: bytes-size(2),
      ancnt     :: bytes-size(2),
      nscnt     :: bytes-size(2),
      arcnt     :: bytes-size(2),
      _payload  :: binary
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
    << _header :: bytes-size(@bytes_in_header), payload :: binary >> = data
    %Protocol.Dns{
      header: header(data),
      data: payload
    }
  end

end
