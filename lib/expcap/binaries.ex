defmodule ExPcap.Binaries do

  def reverse_binary(<<>>, acc) do
    acc
  end

  def reverse_binary(<<h :: bytes-size(1), t :: binary>>, acc) do
    reverse_binary(t, h <> acc)
  end

  def reverse_binary(b) do
    reverse_binary(b, <<>>)
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

end
