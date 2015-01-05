defmodule ExPcap.Binaries do

  def to_binary(list) do
    to_binary(list, <<>>)
  end

  def to_binary([], acc) do
    acc
  end

  def to_binary(list, acc) do
    [h | t] = list
    to_binary(t, acc <> <<h>>)
  end

  def to_list(b) do
    to_list(b, [])
  end

  def to_list(<<>>, acc) do
    Enum.reverse acc
  end

  def to_list(b, acc) do
    <<a :: size(8), rest :: binary>> = b
    to_list(rest, [a | acc])
  end

  def reverse_binary(<<>>, acc) do
    acc
  end

  def reverse_binary(<<h :: bytes-size(1), t :: binary>>, acc) do
    reverse_binary(t, h <> acc)
  end

  def reverse_binary(b) do
    reverse_binary(b, <<>>)
  end

  def to_uint4(b) do
    <<n :: unsigned-integer-size(4)>> = b
    n
  end

  def to_uint16(b) do
    <<n :: unsigned-integer-size(16)>> = b
    n
  end

  def to_uint32(b) do
    <<n :: unsigned-integer-size(32)>> = b
    n
  end

  def to_int32(b) do
    <<n :: signed-integer-size(32)>> = b
    n
  end

  def to_string(b) do
    Inspect.Algebra.to_doc(b, %Inspect.Opts{width: 80})
  end

  def to_raw(_b) do
    # to_string(b)
    "... redacted ..."
  end

  def to_hex(b) do
    "0x" <> Base.encode16(b)
  end

end
