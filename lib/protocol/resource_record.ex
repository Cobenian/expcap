defimpl String.Chars, for: Protocol.Dns.Question do
  def to_string(dns) do
    String.strip("""
      name:               #{dns.name}
      qtype:              #{dns.qtype} #{Protocol.Dns.ResourceRecord.type_name(dns.qtype)}
      qclass:             #{dns.qclass} #{Protocol.Dns.ResourceRecord.class_name(dns.qclass)}
    """)
  end
end

defimpl String.Chars, for: Protocol.Dns.ResourceRecord do
  def to_string(dns) do
    String.strip("""
      name:               #{dns.name}
      type:               #{dns.type} #{Protocol.Dns.ResourceRecord.type_name(dns.type)}
      class:              #{dns.class} #{Protocol.Dns.ResourceRecord.class_name(dns.class)}
      ttl:                #{dns.ttl}
      rdlen:              #{dns.rdlen}
      rdata:              #{ExPcap.Binaries.to_string(dns.rdata)}
    """)
  end
end

defmodule Protocol.Dns.Question do
  defstruct name:     "",
            qtype:    0,
            qclass:   0
end

defmodule Protocol.Dns.ResourceRecord do

  defstruct name:     "",
            type:     0,
            class:    0,
            ttl:      0,
            rdlen:    0,
            rdata:    <<>>

  def class_name(class) do
    case class do
      1   -> :IN
      3   -> :CH
      _   -> :""
    end
  end

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

  def read_bytes(data, len) do
    # IO.puts "looking for #{len} bytes from #{byte_size(data)}"
    # IO.inspect data
    <<
      bytes   :: bytes-size(len),
      rest    :: binary
    >> = data
    {bytes, rest}
  end

  def read_label(message, data, acc, at_end) do
    <<
      len           :: unsigned-integer-size(8),
      rest          :: binary
    >> = data
    if len == 0 do
      {Enum.join(Enum.reverse(acc), "."), rest}
    else
      # IO.puts "time to read #{len} bytes"
      {bytes, rest} = read_bytes(rest, len)
      # IO.puts "read label segment:"
      # IO.inspect bytes
      read_name(message, rest, [bytes | acc], at_end)
    end
  end

  def read_offset(message, data, acc) do
    require Bitwise
    <<
      pointer :: unsigned-integer-size(16),
      rest :: binary
    >> = data
    # IO.puts "pointer:"
    # IO.inspect pointer
    offset = Bitwise.band(0b0011111111111111, pointer)
    # IO.puts "offset is #{offset}"
    {_ignore, bytes_to_use} = read_bytes(message, offset)

    {name, _remaining} = read_name(message, bytes_to_use, acc, true)
    {name, rest}
  end

  def read_name(message, data, acc, at_end) do
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

  def read_name(message, data) do
      read_name(message, data, [], false)
  end

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
    # IO.puts "read question:"
    # IO.inspect question
    {question, rest}
  end

  def read_questions(0, _message, data, acc) do
    {Enum.reverse(acc), data}
  end

  def read_questions(question_count, message, data, acc) do
    {question, rest} = read_question(message, data)

    read_questions(question_count - 1, message, rest, [question | acc])
  end

  def read_questions(question_count, message, data) do
    read_questions(question_count, message, data, [])
  end

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
    # IO.puts "read answer:"
    # IO.inspect answer
    {answer, remaining}
  end

  def read_answers(0, _message, data, acc) do
    {Enum.reverse(acc), data}
  end

  def read_answers(answer_count, message, data, acc) do
    {answer, rest} = read_answer(message, data)

    read_answers(answer_count - 1, message, rest, [answer | acc])
  end

  def read_answers(answer_count, message, data) do
    read_answers(answer_count, message, data, [])
  end

  def read_dns(header, message, data) do
    {questions, data}     = read_questions(header.qdcnt, message, data)
    {answers, data}       = read_answers(header.ancnt, message, data)
    {authorities, data}   = read_answers(header.nscnt, message, data)
    {additionals, data}   = read_answers(header.arcnt, message, data)

    {questions, answers, authorities, additionals, data}
  end

end
