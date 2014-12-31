defimpl String.Chars, for: ExPcap.MagicNumber do
  def to_string(magic_number) do
    String.strip("""
    magic number:       0x#{String.downcase(Integer.to_string(magic_number.magic, 16))}
      nanoseconds?      #{magic_number.nanos}
      reverse bytes?    #{magic_number.reverse_bytes}
    """)
  end
end

defmodule ExPcap.MagicNumber do

  defstruct reverse_bytes:  false,
            nanos:          false,
            magic:          0x00000000

  @bytes_in_magic 4

  def bytes_in_magic() do
    @bytes_in_magic
  end

  def magic_number(0xd4, 0xc3, 0xb2, 0xa1) do
    %ExPcap.MagicNumber{
      reverse_bytes: true,
      nanos: false,
      magic: 0xd4c3b2a1
    }
  end

  def magic_number(0xa1, 0xb2, 0xc3, 0xd4) do
    %ExPcap.MagicNumber{
      reverse_bytes: false,
      nanos: false,
      magic: 0xa1b2c3d4
    }
  end

  def magic_number(0xa1, 0xb2, 0x3c, 0x4d) do
    %ExPcap.MagicNumber{
      reverse_bytes: false,
      nanos: true,
      magic: 0xa1b2c3d4
    }
  end

  def magic_number(0x4d, 0x3c, 0xb2, 0xa1) do
    %ExPcap.MagicNumber{
      reverse_bytes: true,
      nanos: true,
      magic: 0xa1b2c3d4
    }
  end

  def read_magic(data) do
    <<
    magic1 :: unsigned-integer-size(8),
    magic2 :: unsigned-integer-size(8),
    magic3 :: unsigned-integer-size(8),
    magic4 :: unsigned-integer-size(8)
    >> = data
    magic_number(magic1, magic2, magic3, magic4)
  end

  def from_file(f) do
    IO.binread(f, @bytes_in_magic) |> read_magic
  end

end
