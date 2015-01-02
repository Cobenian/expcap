defimpl String.Chars, for: ExPcap.PacketHeader do
  def to_string(header) do
    String.strip("""
      ts sec:             #{header.ts_sec} (#{Timex.DateFormat.format!(Timex.Date.from(header.ts_sec, :secs), "{ISO}")})
      ts usec:            #{header.ts_usec}
      incl len:           #{header.incl_len}
      orig len:           #{header.orig_len}
    """)
  end
end

defmodule ExPcap.PacketHeader do

  defstruct ts_sec:   0,
            ts_usec:  0,
            incl_len: 0,
            orig_len: 0

  @bytes_in_header 16

  def read_forward(data) do
    <<
      ts_sec    :: unsigned-integer-size(32),
      ts_usec   :: unsigned-integer-size(32),
      incl_len  :: unsigned-integer-size(32),
      orig_len  :: unsigned-integer-size(32)
    >> = data
    %ExPcap.PacketHeader{
      ts_sec:   ts_sec,
      ts_usec:  ts_usec,
      incl_len: incl_len,
      orig_len: orig_len
    }
  end

  def read_reversed(data) do

    import ExPcap.Binaries, only: [reverse_binary: 1, to_uint32: 1 ]

    <<
    ts_sec    :: bytes-size(4),
    ts_usec   :: bytes-size(4),
    incl_len  :: bytes-size(4),
    orig_len  :: bytes-size(4)
    >> = data
    %ExPcap.PacketHeader{
      ts_sec:   ts_sec    |> reverse_binary |> to_uint32,
      ts_usec:  ts_usec   |> reverse_binary |> to_uint32,
      incl_len: incl_len  |> reverse_binary |> to_uint32,
      orig_len: orig_len  |> reverse_binary |> to_uint32
    }
  end

  def from_file(f, global_header) do
    data = IO.binread(f, @bytes_in_header)
    case data do
      :eof -> data
      # {:error, reason} -> data
      _ ->
        if ExPcap.GlobalHeader.reverse_bytes?(global_header) do
          data |> read_reversed
        else
          data |> read_forward
        end
    end
  end

end
