defimpl String.Chars, for: Protocol.Dns.Question do
  def to_string(dns) do
    String.strip("""
      name:               #{dns.name}
      qtype:              #{dns.qtype}
      qclass:             #{dns.qclass}
    """)
  end
end

defimpl String.Chars, for: Protocol.Dns.ResourceRecord do
  def to_string(dns) do
    String.strip("""
      name:               #{dns.name}
      type:               #{dns.type}
      class:              #{dns.class}
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

  def read_bytes(data, len) do
    # IO.puts "looking for #{len} bytes from #{byte_size(data)}"
    # IO.inspect data
    <<
      bytes   :: bytes-size(len),
      rest    :: binary
    >> = data
    {bytes, rest}
  end

  def read_label(data, acc) do
    <<
      len           :: unsigned-integer-size(8),
      rest          :: binary
    >> = data
    if len == 0 do
      {Enum.join(Enum.reverse(acc), "."), rest}
    else
      # IO.puts "time to read #{len} bytes"
      {bytes, rest} = read_bytes(rest, len)
      read_label(rest, [bytes | acc]) # this needs to call into a read_name because an offset can come at the end!
    end
  end

  def read_offset(data) do
    require Bitwise
    <<
      pointer :: unsigned-integer-size(16),
      rest :: binary
    >> = data
    offset = Bitwise.band(0b0011111111111111, pointer)
    # todo read offset from whole message to get actual label value
    {offset, rest}
  end

  def read_name(data) do
    IO.puts "read name from #{ExPcap.Binaries.to_string(data)}"
    if byte_size(data) == 0 do
      {"", <<>>}
    else
      <<
        top_bits        :: bits-size(2),
        _size_bits      :: bits-size(6),
        _rest           :: binary
      >> = data
      case top_bits do
        <<0 :: size(1), 0 :: size(1)>> -> read_label(data, [])
        <<1 :: size(1), 1 :: size(1)>> -> read_offset(data)
      end
    end
  end

  def read_question(data) do
    {name, data_after_name} = read_name(data)
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
    IO.puts "read question:"
    IO.inspect question
    {question, rest}
  end

  def read_questions(0, data, acc) do
    {Enum.reverse(acc), data}
  end

  def read_questions(question_count, data, acc) do
    {question, rest} = read_question(data)

    read_questions(question_count - 1, rest, [question | acc])
  end

  def read_questions(question_count, data) do
    read_questions(question_count, data, [])
  end

  def read_answer(data) do
    {name, data_after_name} = read_name(data)

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
    IO.puts "read answer:"
    IO.inspect answer
    {answer, remaining}
  end

  def read_answers(0, data, acc) do
    {Enum.reverse(acc), data}
  end

  def read_answers(answer_count, data, acc) do
    {answer, rest} = read_answer(data)

    read_answers(answer_count - 1, rest, [answer | acc])
  end

  def read_answers(answer_count, data) do
    read_answers(answer_count, data, [])
  end

  def read_dns(header, data) do
    {questions, data}     = read_questions(header.qdcnt, data)
    {answers, data}       = read_answers(header.ancnt, data)
    {authorities, data}   = read_answers(header.nscnt, data)
    {additionals, data}   = read_answers(header.arcnt, data)

    {questions, answers, authorities, additionals, data}
  end

end
