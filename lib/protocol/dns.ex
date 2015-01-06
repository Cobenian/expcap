defimpl String.Chars, for: Protocol.Dns do
  @doc """
  Prints a DNS packet to a human readable string
  """
  @spec to_string(Protocol.Dns.t) :: String.t
  def to_string(dns) do
    String.strip("""
    DNS:
        #{dns.header}
        Length:           #{byte_size(dns.data)}
        Parsed:
          Questions:
      #{Enum.join(Enum.map(elem(dns.parsed, 0), &String.Chars.to_string/1), "\n  ")}
          Answers:
      #{Enum.join(Enum.map(elem(dns.parsed, 1), &String.Chars.to_string/1), "\n  ")}
          Authorities:
      #{Enum.join(Enum.map(elem(dns.parsed, 2), &String.Chars.to_string/1), "\n  ")}
          Additionals:
      #{Enum.join(Enum.map(elem(dns.parsed, 3), &String.Chars.to_string/1), "\n  ")}
        Raw:              #{ExPcap.Binaries.to_raw(dns.data)}
    """)
  end
end

defimpl String.Chars, for: Protocol.Dns.Header do
  @doc """
  Prints a DNS packet header to a human readable string
  """
  @spec to_string(Protocol.Dns.t) :: String.t
  def to_string(dns) do
    String.strip("""
        id:               #{ExPcap.Binaries.to_string(dns.id)} #{ExPcap.Binaries.to_hex(dns.id)}
        qr:               #{ExPcap.Binaries.to_string(dns.qr)} #{Protocol.Dns.Header.qr_name(dns.qr)}
        opcode:           #{ExPcap.Binaries.to_string(dns.opcode)} #{Protocol.Dns.Header.opcode_name(dns.opcode)}
        aa:               #{ExPcap.Binaries.to_string(dns.aa)} #{Protocol.Dns.Header.aa_name(dns.aa)}
        tc:               #{ExPcap.Binaries.to_string(dns.tc)} #{Protocol.Dns.Header.tc_name(dns.tc)}
        rd:               #{ExPcap.Binaries.to_string(dns.rd)} #{Protocol.Dns.Header.rd_name(dns.rd)}
        ra:               #{ExPcap.Binaries.to_string(dns.ra)} #{Protocol.Dns.Header.ra_name(dns.ra)}
        z:                #{ExPcap.Binaries.to_string(dns.z)} #{Protocol.Dns.Header.z_name(dns.z)}
        rcode:            #{ExPcap.Binaries.to_string(dns.rcode)} #{Protocol.Dns.Header.rcode_name(dns.rcode)}
        qdcnt:            #{ExPcap.Binaries.to_string(dns.qdcnt)}
        ancnt:            #{ExPcap.Binaries.to_string(dns.ancnt)}
        nscnt:            #{ExPcap.Binaries.to_string(dns.nscnt)}
        arcnt:            #{ExPcap.Binaries.to_string(dns.arcnt)}
    """)
  end
end

defimpl PayloadType, for: Protocol.Dns do
  @doc """
  Returns the parser that will parse the body of the DNS packet
  """
  @spec payload_parser(Protocol.Dns.t) :: PayloadType.t
  def payload_parser(_dns) do
    nil
    # case dns.header.qr do
    #   <<0 :: size(1)>> -> Protocol.Dns.Question
    #   <<1 :: size(1)>> -> Protocol.Dns.ResourceRecord
    # end
  end
end

defimpl PayloadParser, for: Protocol.Dns do
  @doc """
  Parses the body of the DNS packet
  """
  @spec from_data(binary) :: any
  def from_data(data) do
    Protocol.Dns.from_data data
  end
end

defmodule Protocol.Dns.Header do

  @moduledoc """
  A parsed DNS packet header
  """

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

  @type t :: %Protocol.Dns.Header{
    id:      binary,
    qr:      bitstring,
    opcode:  bitstring,
    aa:      bitstring,
    tc:      bitstring,
    rd:      bitstring,
    ra:      bitstring,
    z:       bitstring,
    rcode:   bitstring,
    qdcnt:   non_neg_integer,
    ancnt:   non_neg_integer,
    nscnt:   non_neg_integer,
    arcnt:   non_neg_integer
  }

  @doc """
  Is this a query or a response?
  """
  @spec qr_name(binary) :: :QUERY | :ANSWER
  def qr_name(qr) do
    case qr do
      <<0 :: size(1)>>    -> :QUERY
      <<1 :: size(1)>>    -> :ANSWER
    end
  end

  @doc """
  Is this response authoritative?
  """
  @spec aa_name(binary) :: :NOT_AUTHORITATIVE | :AUTHORITATIVE | :""
  def aa_name(aa) do
    case aa do
      <<0 :: size(1)>>    -> :NOT_AUTHORITATIVE
      <<1 :: size(1)>>    -> :AUTHORITATIVE
      _                   -> :""
    end
  end

  @doc """
  Is this response truncated?
  """
  @spec tc_name(binary) :: :NOT_TRUNCATED | :TRUNCATED | :""
  def tc_name(tc) do
    case tc do
      <<0 :: size(1)>>    -> :NOT_TRUNCATED
      <<1 :: size(1)>>    -> :TRUNCATED
      _                   -> :""
    end
  end

  @doc """
  Is recursion desired?
  """
  @spec rd_name(binary) :: :NO_RECURSION_DESIRED | :RECURSION_DESIRED | :""
  def rd_name(rd) do
    case rd do
      <<0 :: size(1)>>    -> :NO_RECURSION_DESIRED
      <<1 :: size(1)>>    -> :RECURSION_DESIRED
      _                   -> :""
    end
  end

  @doc """
  Is recursion available?
  """
  @spec ra_name(binary) :: :NO_RECURSION_AVAILABLE | :RECURSION_AVAILABLE | :""
  def ra_name(ra) do
    case ra do
      <<0 :: size(1)>>    -> :NO_RECURSION_AVAILABLE
      <<1 :: size(1)>>    -> :RECURSION_AVAILABLE
      _                   -> :""
    end
  end

  @doc """
  The first bit is reserved.
  The second bit indciates if the response was authenticated or not.
  The third bit indciates if the data was authenticated or not.
  """
  @spec z_name(binary) :: :atom
  def z_name(z) do
    case z do
      <<0b000 :: size(3)>>    -> :"RESERVED - NOT AUTHENTICATED - NON AUTHENTICATED DATA"
      <<0b001 :: size(3)>>    -> :"RESERVED - NOT AUTHENTICATED - AUTHENTICATED DATA"
      <<0b010 :: size(3)>>    -> :"RESERVED - AUTHENTICATED - NON AUTHENTICATED DATA"
      <<0b011 :: size(3)>>    -> :"RESERVED - AUTHENTICATED - AUTHENTICATED DATA"
      <<0b100 :: size(3)>>    -> :"RESERVED - NOT AUTHENTICATED - NON AUTHENTICATED DATA"
      <<0b101 :: size(3)>>    -> :"RESERVED - NOT AUTHENTICATED - AUTHENTICATED DATA"
      <<0b110 :: size(3)>>    -> :"RESERVED - AUTHENTICATED - NON AUTHENTICATED DATA"
      <<0b111 :: size(3)>>    -> :"RESERVED - AUTHENTICATED - AUTHENTICATED DATA"
    end
  end

  @doc """
  What is the op code of this DNS packet?
  """
  @spec opcode_name(non_neg_integer) :: :QUERY | :STATUS | :NOTIFY | :UPDATE | :""
  def opcode_name(opcode) do
    case opcode do
      0   -> :QUERY
      2   -> :STATUS
      4   -> :NOTIFY
      5   -> :UPDATE
      _   -> :""
    end
  end

  @doc """
  What is the r code of this DNS packet?
  """
  @spec rcode_name(non_neg_integer) :: :atom
  def rcode_name(rcode) do
    case rcode do
      0   -> :NOERROR
      1   -> :FORMERR
      2   -> :SERVFAIL
      3   -> :NXDOMAIN
      4   -> :NOTIMPL
      5   -> :REFUSED
      6   -> :YXDOMAIN
      7   -> :YXRRSET
      8   -> :NXRRSET
      9   -> :NOTAUTH
      10  -> :NOTZONE
      16  -> :BADVERS_OR_BADSIG
      17  -> :BADKEY
      18  -> :BADTIME
      19  -> :BADMODE
      20  -> :BADNAME
      21  -> :BADALG
      22  -> :BADTRUNC
      _   -> :""
    end
  end

end

defmodule Protocol.Dns do

  @moduledoc """
  A parsed DNS packet
  """

  @bytes_in_header 12

  defstruct header: %Protocol.Dns.Header{},
            parsed: {
                      [%Protocol.Dns.Question{}],         # questions
                      [%Protocol.Dns.ResourceRecord{}],   # answers
                      [%Protocol.Dns.ResourceRecord{}],   # authorities
                      [%Protocol.Dns.ResourceRecord{}],   # additionals
                      <<>>      # leftover bytes
                    },
            data: <<>>

  @type t :: %Protocol.Dns{
    header: Protocol.Dns.Header.t,
    parsed: {
      [Protocol.Dns.Question.t],         # questions
      [Protocol.Dns.ResourceRecord.t],   # answers
      [Protocol.Dns.ResourceRecord.t],   # authorities
      [Protocol.Dns.ResourceRecord.t],   # additionals
      binary
      },
    data: binary
  }

  @doc """
  Parses a DNS header
  """
  @spec header(binary) :: Protocol.Dns.Header.t
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
      qdcnt     :: unsigned-integer-size(16),
      ancnt     :: unsigned-integer-size(16),
      nscnt     :: unsigned-integer-size(16),
      arcnt     :: unsigned-integer-size(16),
      _payload  :: binary
    >> = data
    %Protocol.Dns.Header{
      id:     id,
      qr:     qr,
      opcode: ExPcap.Binaries.to_uint4(opcode),
      aa:     aa,
      tc:     tc,
      rd:     rd,
      ra:     ra,
      z:      z,
      rcode:  ExPcap.Binaries.to_uint4(rcode),
      qdcnt:  qdcnt,
      ancnt:  ancnt,
      nscnt:  nscnt,
      arcnt:  arcnt
    }
  end

  @doc """
  Returns a parsed DNS packet
  """
  @spec from_data(binary) :: Protocol.Dns.t
  def from_data(data) do
    << _header :: bytes-size(@bytes_in_header), payload :: binary >> = data
    header = header(data)
    dns = Protocol.Dns.ResourceRecord.read_dns(header, data, payload)
    %Protocol.Dns{
      header: header,
      parsed: dns,
      data: payload
    }
  end

end
