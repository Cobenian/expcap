defimpl String.Chars, for: Protocol.Dns.Question do
  @doc """
  Prints a DNS question to a human readable string
  """
  @spec to_string(binary) :: String.t
  def to_string(dns) do
    """
      name:               #{dns.name}
      qtype:              #{dns.qtype} #{Protocol.Dns.ResourceRecord.type_name(dns.qtype)}
      qclass:             #{dns.qclass} #{Protocol.Dns.ResourceRecord.class_name(dns.qclass)}
    """ |> String.trim
  end
end

defimpl String.Chars, for: Protocol.Dns.ResourceRecord do
  @doc """
  Prints a DNS resource record to a human readable string
  """
  @spec to_string(binary) :: String.t
  def to_string(dns) do
    """
      name:               #{dns.name}
      type:               #{dns.type} #{Protocol.Dns.ResourceRecord.type_name(dns.type)}
      class:              #{dns.class} #{Protocol.Dns.ResourceRecord.class_name(dns.class)}
      ttl:                #{dns.ttl}
      rdlen:              #{dns.rdlen}
      rdata:              #{ExPcap.Binaries.to_string(dns.rdata)} #{Protocol.Dns.ResourceRecord.rdata_string(dns)}
    """ |> String.trim
  end
end

defmodule Protocol.Dns.Question do

  @moduledoc """
  A parsed DNS question
  """

  defstruct name:     "",
            qtype:    0,
            qclass:   0

  @type t :: %Protocol.Dns.Question{
    name: String.t,
    qtype: non_neg_integer,
    qclass: non_neg_integer
  }
end

defmodule Protocol.Dns.ResourceRecord do

  @moduledoc """
  A parsed DNS resource record
  """

  defstruct name:     "",
            type:     0,
            class:    0,
            ttl:      0,
            rdlen:    0,
            rdata:    <<>>

  @type t :: %Protocol.Dns.ResourceRecord{
    name: String.t,
    type: non_neg_integer,
    class: non_neg_integer,
    ttl: non_neg_integer,
    rdlen: non_neg_integer,
    rdata: binary
  }

  @doc """
  Prints rdata to a human readable string. Very few rr types are supported.
  """
  @spec rdata_string(binary) :: String.t
  def rdata_string(dns) do
    case dns.type do
      1   -> # A
        dns.rdata
        |> ExPcap.Binaries.to_list
        |> Enum.join(".")
      16  -> # TXT
        dns.rdata
        |> String.codepoints
        |> Enum.filter(&String.printable?/1)
      28  -> # AAAA
        dns.rdata
        |> ExPcap.Binaries.to_list
        |> Enum.chunk(2)
        |> Enum.map(&ExPcap.Binaries.to_binary/1)
        |> Enum.map(&Base.encode16/1)
        |> Enum.join(":")
      _   ->
        ""
    end
  end

  @doc """
  The dclass name of this packet
  """
  @spec class_name(non_neg_integer) :: :IN | :CH | :""
  def class_name(class) do
    case class do
      1   -> :IN
      3   -> :CH
      _   -> :""
    end
  end

  @doc """
  The rr type
  """
  @spec type_name(non_neg_integer) :: :atom
  def type_name(type) do
    case type do
      1   -> :A
      2   -> :NS
      5   -> :CNAME
      6   -> :SOA
      12  -> :PTR
      15  -> :MX
      16  -> :TXT
      24  -> :SIG
      25  -> :KEY
      28  -> :AAAA
      29  -> :LOC
      33  -> :SRV
      37  -> :CERT
      39  -> :DNAME
      43  -> :DS
      45  -> :IPSECKEY
      46  -> :RRSIG
      47  -> :NSEC
      48  -> :DNSKEY
      50  -> :NSEC3
      51  -> :NSEC3PARAM
      250 -> :TSIG
      251 -> :IXFR
      252 -> :AXFR
      _   -> :""
    end
  end

  @doc """
  Reads the 'len' number of bytes from the binary and returns a tuple of the
  bytes read the remaining bytes.
  """
  @spec read_bytes(binary, non_neg_integer) :: {binary, binary}
  def read_bytes(data, len) do
    <<
      bytes   :: bytes-size(len),
      rest    :: binary
    >> = data
    {bytes, rest}
  end

  @doc """
  Reads a label (such as 'ns1.google.com'). It technically reads one label at a
  time and recurs until the end of the label is reached.
  """
  @spec read_label(binary, binary, list, boolean) :: {String.t, binary}
  def read_label(message, data, acc, at_end) do
    <<
      len           :: unsigned-integer-size(8),
      rest          :: binary
    >> = data
    if len == 0 do
      {acc |> Enum.reverse |> Enum.join("."), rest}
    else
      {bytes, rest} = read_bytes(rest, len)
      read_name(message, rest, [bytes | acc], at_end)
    end
  end

  @doc """
  Reads the offset position and then returns the label at the offset in the
  entire 'message'. Returns a tuple of the label read and the remaining bytes
  not yet read.
  """
  @spec read_offset(binary, binary, list) :: {String.t, binary}
  def read_offset(message, data, acc) do
    require Bitwise
    <<
      pointer :: unsigned-integer-size(16),
      rest :: binary
    >> = data
    offset = Bitwise.band(0b0011111111111111, pointer)
    {_ignore, bytes_to_use} = read_bytes(message, offset)

    {name, _remaining} = read_name(message, bytes_to_use, acc, true)
    {name, rest}
  end

  @doc """
  Reads a name (label or offset) from the data and returns a tuple with the name
  read and the remaining bytes not yet read.
  """
  @spec read_name(binary, binary, list, boolean) :: {String.t, binary}
  def read_name(message, data, acc, _at_end) do
    <<
      top_bits        :: bits-size(2),
      _size_bits      :: bits-size(6),
      _rest           :: binary
    >> = data
    case top_bits do
      <<0 :: size(1), 0 :: size(1)>> -> read_label(message, data, acc, false)
      <<1 :: size(1), 1 :: size(1)>> -> read_offset(message, data, acc)
    end
  end

  @doc """
  Reads a name from the data and returns a tuple of the name read and the
  reamining bytes that have not been read yet.
  """
  @spec read_name(binary, binary) :: {String.t, binary}
  def read_name(message, data) do
      read_name(message, data, [], false)
  end

  @doc """
  Reads a DNS question from the 'data'. Returns a tuple of the question and the
  remaining bytes.
  """
  @spec read_question(binary, binary) :: {Protocol.Dns.Question.t, binary}
  def read_question(message, data) do
    {name, data_after_name} = read_name(message, data)
    <<
      qtype     :: unsigned-integer-size(16),
      qclass    :: unsigned-integer-size(16),
      rest      :: binary
    >> = data_after_name
    question = %Protocol.Dns.Question{
      name: name,
      qtype: qtype,
      qclass: qclass
    }
    {question, rest}
  end

  @doc """
  Returns a tuple with the list of the questions in this DNS packet and a binary
  of the remaining bytes that have not yet been read.
  """
  @spec read_questions(0, binary, binary, list) :: {[Protocol.Dns.Question.t], binary}
  def read_questions(0, _message, data, acc) do
    {Enum.reverse(acc), data}
  end

  @doc """
  Returns a tuple with the list of the questions in this DNS packet and a binary
  of the remaining bytes that have not yet been read.
  """
  @spec read_questions(non_neg_integer, binary, binary, list) :: {[Protocol.Dns.Question.t], binary}
  def read_questions(question_count, message, data, acc) do
    {question, rest} = read_question(message, data)

    read_questions(question_count - 1, message, rest, [question | acc])
  end

  @doc """
  Returns a tuple with the list of the questions in this DNS packet and a binary
  of the remaining bytes that have not yet been read.
  """
  @spec read_questions(non_neg_integer, binary, binary) :: {[Protocol.Dns.Question.t], binary}
  def read_questions(question_count, message, data) do
    read_questions(question_count, message, data, [])
  end

  @doc """
  Reads an answer from the 'data' and returns a tuple of the resource record
  and remaining bytes.
  """
  @spec read_answer(binary, binary) :: {Protocol.Dns.ResourceRecord.t, binary}
  def read_answer(message, data) do
    {name, data_after_name} = read_name(message, data)

    <<
      type      :: unsigned-integer-size(16),
      class     :: unsigned-integer-size(16),
      ttl       :: unsigned-integer-size(32),
      rdlen     :: unsigned-integer-size(16),
      rest      :: binary
    >> = data_after_name
    <<
      rdata     :: bytes-size(rdlen),
      remaining :: binary
    >> = rest
    answer = %Protocol.Dns.ResourceRecord{
      name: name,
      type: type,
      class: class,
      ttl: ttl,
      rdlen: rdlen,
      rdata: rdata
    }
    {answer, remaining}
  end

  @doc """
  Returns a list of the answers (resource records) in this section of the DNS
  packet. The section may be the answer, authoritative or additional sections,
  this code is generic so it doesn't care which section is being read.
  """
  @spec read_answers(0, binary, binary, list) :: {[Protocol.Dns.ResourceRecord.t], binary}
  def read_answers(0, _message, data, acc) do
    {Enum.reverse(acc), data}
  end

  @doc """
  Returns a list of the answers (resource records) in this section of the DNS
  packet. The section may be the answer, authoritative or additional sections,
  this code is generic so it doesn't care which section is being read.
  """
  @spec read_answers(non_neg_integer, binary, binary, list) :: {[Protocol.Dns.ResourceRecord.t], binary}
  def read_answers(answer_count, message, data, acc) do
    {answer, rest} = read_answer(message, data)

    read_answers(answer_count - 1, message, rest, [answer | acc])
  end

  @doc """
  Returns a list of the answers (resource records) in this section of the DNS
  packet. The section may be the answer, authoritative or additional sections,
  this code is generic so it doesn't care which section is being read.
  """
  @spec read_answers(non_neg_integer, binary, binary) :: {[Protocol.Dns.ResourceRecord.t], binary}
  def read_answers(answer_count, message, data) do
    read_answers(answer_count, message, data, [])
  end

  @doc """
  Returns the list of questions in the DNS packet and answer,
  authoritative and additional sections.  Finally, the tuple returned contains
  the remaining bytes if there are any.
  """
  @spec read_dns(Protocol.Dns.Header.t, binary, binary) :: {
    [Protocol.Dns.Question.t],
    [Protocol.Dns.ResourceRecord.t],
    [Protocol.Dns.ResourceRecord.t],
    [Protocol.Dns.ResourceRecord.t],
    binary
  }
  def read_dns(header, message, data) do
    {questions, data}     = read_questions(header.qdcnt, message, data)
    {answers, data}       = read_answers(header.ancnt, message, data)
    {authorities, data}   = read_answers(header.nscnt, message, data)
    {additionals, data}   = read_answers(header.arcnt, message, data)

    {questions, answers, authorities, additionals, data}
  end

end
