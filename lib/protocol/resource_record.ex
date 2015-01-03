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

defimpl PayloadType, for: Protocol.Dns.Question do
  def payload_parser(_data) do
    nil
  end
end

defimpl PayloadType, for: Protocol.Dns.ResourceRecord do
  def payload_parser(_data) do
    nil
  end
end

defimpl PayloadParser, for: Protocol.Dns.ResourceRecord do
  def from_data(data) do
    Protocol.Dns.ResourceRecord.from_data data
  end
end

defimpl PayloadParser, for: Protocol.Dns.Question do
  def from_data(data) do
    Protocol.Dns.Question.from_data data
  end
end

defmodule Protocol.Dns.Question do
  defstruct name:     "",
            qtype:    0,
            qclass:   0

  def from_data(data) do
    IO.puts "reading dns question"
    {name, data_after_name} = Protocol.Dns.ResourceRecord.read_name(data)
    IO.puts name
    <<
    qtype     :: unsigned-integer-size(16),
    qclass    :: unsigned-integer-size(16),
    rest     :: binary
    >> = data_after_name
    a = %Protocol.Dns.Question{
      name: name,
      qtype: qtype,
      qclass: qclass
    }
    IO.puts "question is #{a}"
    IO.puts "ignoring #{byte_size(rest)} bytes: #{ExPcap.Binaries.to_string(rest)}"
    a
  end
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
      {Enum.reverse(acc), rest}
    else
      # IO.puts "time to read #{len} bytes"
      {bytes, rest} = read_bytes(rest, len)
      read_label(rest, [bytes | acc])
    end
  end

  def read_offset(_data) do
    {nil, nil} # todo implement me
  end

  def read_name(data) do
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

  def from_data(data) do
    IO.puts "reading dns response"
    {name, data_after_name} = read_name(data)
    IO.inspect name
    IO.inspect "bryan"
    IO.inspect data_after_name
    <<
      checksum  :: bytes-size(6),
      type      :: unsigned-integer-size(16),
      class     :: unsigned-integer-size(16),
      ttl       :: unsigned-integer-size(32),
      rdlen     :: unsigned-integer-size(16),
      rest      :: binary
    >> = data_after_name
    <<
      rdata     :: bytes-size(rdlen),
      ignore    :: binary
    >> = rest
    r = %Protocol.Dns.ResourceRecord{
      name: name,
      type: type,
      class: class,
      ttl: ttl,
      rdlen: rdlen,
      rdata: rdata
    }
    IO.puts r
    IO.puts "ignoring #{byte_size(ignore)} bytes: #{ExPcap.Binaries.to_string(ignore)}"
    r
  end

end
