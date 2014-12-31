defmodule ExPcap.GlobalHeader do

  defstruct magic_number:   0,
            version_major:  0,
            version_minor:  0,
            thiszone:       0,
            sigfigs:        0,
            snaplen:        0,
            network:        0   # determines the payload type (http://www.tcpdump.org/linktypes.html)

  @bytes_in_header 24 - ExPcap.MagicNumber.bytes_in_magic

  def reverse_bytes?(global_header) do
    global_header.magic_number.reverse_bytes
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
    %ExPcap.GlobalHeader{magic_number: magic_number, version_major: version_major,
                  version_minor: version_minor, thiszone: thiszone,
                  sigfigs: sigfigs, snaplen: snaplen, network: network}
  end

  def read_reversed(data, magic_number) do

    import ExPcap.Binaries, only: [reverse_binary: 1, to_uint16: 1, to_uint32: 1, to_int32: 1 ]

    <<
    version_major :: bytes-size(2),
    version_minor :: bytes-size(2),
    thiszone      :: bytes-size(4), # GMT to local correction
    sigfigs       :: bytes-size(4), # accuracy of timestamps
    snaplen       :: bytes-size(4), # max length of captured packets, in octets
    network       :: bytes-size(4)  # data link type
    >> = data

    %ExPcap.GlobalHeader{
      magic_number:   magic_number,
      version_major:  version_major |> reverse_binary |> to_uint16,
      version_minor:  version_minor |> reverse_binary |> to_uint16,
      thiszone:       thiszone      |> reverse_binary |> to_int32,
      sigfigs:        sigfigs       |> reverse_binary |> to_uint32,
      snaplen:        snaplen       |> reverse_binary |> to_uint32,
      network:        network       |> reverse_binary |> to_uint32
    }
  end

  def from_file(f, magic_number) do
    data = IO.binread(f, @bytes_in_header)
    if magic_number.reverse_bytes do
      data |> read_reversed(magic_number)
    else
      data |> read_forward(magic_number)
    end
  end
end
