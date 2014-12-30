defmodule GlobalHeader do

  defstruct magic_number: 0, version_major: 0, version_minor: 0, thiszone: 0,
            sigfigs: 0, snaplen: 0, network: 0

  @bytes_in_header 24
  @bytes_in_magic 4

  def magic_number(0xd4, 0xc3, 0xb2, 0xa1) do
    [reverse_bytes: true, nanos: false, magic: 0xd4c3b2a1]
  end

  def magic_number(0xa1, 0xb2, 0xc3, 0xd4) do
    [reverse_bytes: false, nanos: false, magic: 0xa1b2c3d4]
  end

  def magic_number(0xa1, 0xb2, 0x3c, 0x4d) do
    [reverse_bytes: false, nanos: true, magic: 0xa1b2c3d4]
  end

  def magic_number(0x4d, 0x3c, 0xb2, 0xa1) do
    [reverse_bytes: true, nanos: true, magic: 0xa1b2c3d4]
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

  def read_forward(data, magic_number) do
    <<
      version_major :: unsigned-integer-size(16),
      version_minor :: unsigned-integer-size(16),
      thiszone      ::   signed-integer-size(32), # GMT to local correction
      sigfigs       :: unsigned-integer-size(32), # accuracy of timestamps
      snaplen       :: unsigned-integer-size(32), # max length of captured packets, in octets
      network       :: unsigned-integer-size(32)  # data link type
    >> = data
    %GlobalHeader{magic_number: magic_number, version_major: version_major,
                  version_minor: version_minor, thiszone: thiszone,
                  sigfigs: sigfigs, snaplen: snaplen, network: network}
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

  def read_reversed(data, magic_number) do
    <<
    version_major :: bytes-size(2),
    version_minor :: bytes-size(2),
    thiszone      :: bytes-size(4), # GMT to local correction
    sigfigs       :: bytes-size(4), # accuracy of timestamps
    snaplen       :: bytes-size(4), # max length of captured packets, in octets
    network       :: bytes-size(4)  # data link type
    >> = data

    %GlobalHeader{
      magic_number:   magic_number,
      version_major:  version_major |> reverse_binary |> to_uint16,
      version_minor:  version_minor |> reverse_binary |> to_uint16,
      thiszone:       thiszone      |> reverse_binary |> to_int32,
      sigfigs:        sigfigs       |> reverse_binary |> to_uint32,
      snaplen:        snaplen       |> reverse_binary |> to_uint32,
      network:        network       |> reverse_binary |> to_uint32
    }
  end

  def from_file(f) do
    magic = IO.binread(f, @bytes_in_magic) |> read_magic
    [reverse_bytes: reverse_bytes, nanos: _nanos, magic: magic_number] = magic
    data = IO.binread(f, @bytes_in_header - @bytes_in_magic)
    if reverse_bytes do
      data |> read_reversed(magic_number)
    else
      data |> read_forward(magic_number)
    end
  end
end
