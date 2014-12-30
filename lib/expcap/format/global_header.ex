defmodule GlobalHeader do

  defstruct magic_number: 0, version_major: 0, version_minor: 0, thiszone: 0,
            sigfigs: 0, snaplen: 0, network: 0

  def read(data) do
    <<
      magic_number  :: unsigned-integer-size(32),
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

  def read_file(f) do
    File.open!(f, [:read], fn(file) ->
        IO.binread(file, 24) # 24 bytes in the header
    end)
  end

  def from_file(f) do
    IO.binread(f, 24) # 24 bytes in the header
    |> read
  end
end
