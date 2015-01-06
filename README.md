ExPcap
======

[![hex.pm Custom](https://img.shields.io/badge/expcap-Elixir-brightgreen.svg)](https://hex.pm/packages/expcap)
[![hex.pm Version](https://img.shields.io/hexpm/v/expcap.svg)](https://hex.pm/packages/expcap)
[![hex.pm License](https://img.shields.io/hexpm/l/plug.svg)](https://hex.pm/packages/expcap)

A PCAP library written in Elixir. This does not wrap a C or Erlang PCAP library,
rather it attempts to be an idiomatic Elixir library.

This library parses pcap files, however it does not yet support most protocols
that can be contained within a pcap file. The only supported protocols at the
moment are:

* Ethernet
* IPv4
* UDP
* DNS

## Add Dependency

In mix.exs add a dependency:

    {:expcap, "~> 0.1.0"}

## Documentation

Documentation can be found at http://cobenian.github.io/expcap

## Documentation

You must have run mix deps.get and mix deps.compile first.

    mix docs

## Build

You must have Elixir 1.0.0+ installed along with mix.

    mix deps.get
    mix deps.compile
    mix compile
    mix escript.build

## Test

You must have run mix deps.get and mix deps.compile first.

    mix test

## Run via Escript

Once the project has been built, the following escript can be run:

    ./expcap -f <path-file-pcap-file>

A sample DNS cap file can be found in test/data/dns.cap. This file is provided
by Wireshark as a sample capture.

    ./expcap -f test/data/dns.cap

## Programmatic Use

Here is a sample using mix:

    iex -S mix
    iex> ExPcap.from_file "test/data/dns.cap"

If you want to print the string in a more user friendly format:

    iex -S mix
    iex> "test/data/dns.cap" |> ExPcap.from_file |> String.Chars.to_string

### Windows

Escript does not run on Windows so the expcap escript will not work. However,
the code in this library should work on Windows if used as an Elixir library.
This has *not* been tested that we are aware of.

## Adding Support For Additional Protocols

Adding support for additional protocols is not difficult. Any protocol that
may contain your protocol in its body should be updated to indicate that your
protocol is supported.

* Update encapsulating protocols to be aware of the new protocol

For example, if we are adding the UDP protocol and it can be encapsulated in
IPv4 packets, we need to modify the IPv4 PayloadType protocol. In this case we
would add the following line:

```elixir
    <<17>> -> Protocol.Udp
```

Note that each protocol is different in this regard. For example, in IPv4 the
header contains a 'protocol' field that indicates the content type of the body.
The new IPv4 PayloadType implementation would look like:

```elixir
    defimpl PayloadType, for: Protocol.Ipv4 do
      @doc """
      Returns the parser that will parse the body of this IPv4 packet.
      """
      @spec payload_parser(binary) :: PayloadParser.t
      def payload_parser(data) do
        case data.header.protocol do
          <<06>> -> Protocol.Tcp
          <<17>> -> Protocol.Udp
        end
      end
    end
```

Bare Bones:

```elixir
    defimpl PayloadType, for: Protocol.Ipv4 do
      def payload_parser(data) do
        case data.header.protocol do
          <<06>> -> Protocol.Tcp
          <<17>> -> Protocol.Udp
        end
      end
    end
```

* Create a module and struct for your protocol

For many protocols this means having header and data sections only. You may
want to include a "parsed data" element as well.  Here is an example:

```elixir
    defmodule Protocol.Udp do
      @moduledoc """
      A parsed UDP packet
      """

      @bytes_in_header 8

      defstruct header: %Protocol.Udp.Header{},
                data: <<>>

      @type t :: %Protocol.Udp{
        header: Protocol.Udp.Header.t,
        data: binary
      }
    end

```

Bare Bones:

```elixir
    defmodule Protocol.Udp do
      defstruct header: %Protocol.Udp.Header{},
                data: <<>>
    end
```

* Create a struct for your protocol's header (optional)

This is not strictly required, but is generally a good practice.

Here is an example:

```elixir
    defmodule Protocol.Udp.Header do
      @moduledoc """
      A parsed UDP packet header
      """
      defstruct srcport:     <<>>,
                destport:    <<>>,
                length:      <<>>,
                checksum:    <<>>

      @type t :: %Protocol.Udp.Header{
        srcport:  non_neg_integer,
        destport: non_neg_integer,
        length:   binary,
        checksum: binary
      }
    end
```

Bare Bones:

```elixir
    defmodule Protocol.Udp.Header do
      defstruct srcport:     <<>>,
                destport:    <<>>,
                length:      <<>>,
                checksum:    <<>>
    end
```

* Implement the PayloadType protocol

Example:

```elixir
    defimpl PayloadType, for: Protocol.Udp do
      @doc """
      Returns the parser that will parse the body of the UDP packet
      """
      @spec payload_parser(binary) :: Protocol.Udp.t
      def payload_parser(_data) do
        Protocol.Dns
      end
    end
```

Bare Bones:

```elixir
    defimpl PayloadType, for: Protocol.Udp do
      def payload_parser(_data) do
        Protocol.Dns
      end
    end
```

* Implement the PayloadParser protocol

Example:

```elixir
    defimpl PayloadParser, for: Protocol.Udp do
      @doc """
      Returns the parsed body of the UDP packet
      """
      @spec from_data(binary) :: any
      def from_data(data) do
        Protocol.Udp.from_data data
      end
    end
```

Bare Bones:

```elixir
    defimpl PayloadParser, for: Protocol.Udp do
      def from_data(data) do
        Protocol.Udp.from_data data
      end
    end
```

* Add support for parsing your header (optional if you do not have a header)

Example:

```elixir
    @doc """
    Parses the header of a UDP packet
    """
    @spec header(binary) :: Protocol.Udp.Header.t
    def header(data) do
      <<
      srcport       :: unsigned-integer-size(16),
      destport      :: unsigned-integer-size(16),
      length        :: bytes-size(2),
      checksum      :: bytes-size(2),
      _payload       :: binary
      >> = data
      %Protocol.Udp.Header{
        srcport: srcport,
        destport: destport,
        length: length,
        checksum: checksum
      }
    end
```

Bare Bones:

```elixir
    def header(data) do
      <<
        srcport       :: unsigned-integer-size(16),
        destport      :: unsigned-integer-size(16),
        length        :: bytes-size(2),
        checksum      :: bytes-size(2),
        _payload       :: binary
      >> = data
      %Protocol.Udp.Header{
        srcport: srcport,
        destport: destport,
        length: length,
        checksum: checksum
      }
    end
```

* Add support for parsing your protocol

Example:

```elixir
    @doc """
    Returns a parsed UDP packet
    """
    @spec from_data(binary) :: Protocol.Udp.t
    def from_data(data) do
      << _header :: bytes-size(@bytes_in_header), payload :: binary >> = data
      %Protocol.Udp{
        header: header(data),
        data: payload
      }
    end
```

Bare Bones:

```elixir
    def from_data(data) do
      << _header :: bytes-size(@bytes_in_header), payload :: binary >> = data
      %Protocol.Udp{
        header: header(data),
        data: payload
      }
    end
```

* Add support for printing your header to string (optional if you do not have a header)

Example:

```elixir
    defimpl String.Chars, for: Protocol.Udp.Header do
      @doc """
      Prints a UDP packet header to a human readable string
      """
      @spec to_string(Protocol.Udp.t) :: String.t
      def to_string(udp) do
        String.strip("""
        srcport:          #{udp.srcport}
        srcport:          #{udp.destport}
        length:           #{ExPcap.Binaries.to_uint16(udp.length)}
        checksum:         #{ExPcap.Binaries.to_hex(udp.checksum)}
        """)
      end
    end
```

Bare Bones:

```elixir
    defimpl String.Chars, for: Protocol.Udp.Header do
      def to_string(udp) do
        String.strip("""
        srcport:          #{udp.srcport}
        srcport:          #{udp.destport}
        length:           #{ExPcap.Binaries.to_uint16(udp.length)}
        checksum:         #{ExPcap.Binaries.to_hex(udp.checksum)}
        """)
      end
    end
```

* Add support for printing your protocol to string

Example:

```elixir
    defimpl String.Chars, for: Protocol.Udp do
      @doc """
      Prints a UDP packet to a human readable string
      """
      @spec to_string(Protocol.Udp.t) :: String.t
      def to_string(udp) do
        String.strip("""
        Udp:
        #{udp.header}
        Length:           #{byte_size(udp.data)}
        Raw:              #{ExPcap.Binaries.to_raw(udp.data)}
        """)
      end
    end
```

Bare Bones:

```elixir
    defimpl String.Chars, for: Protocol.Udp do
      def to_string(udp) do
        String.strip("""
        Udp:
        #{udp.header}
        Length:           #{byte_size(udp.data)}
        Raw:              #{ExPcap.Binaries.to_raw(udp.data)}
        """)
      end
    end
```

## Limitations

* Very few protocols are supported at this time.
* Well formed pcap files can be parsed properly, however corrupted pcap files
may not have helpful error messages.
* Escript will not run on Windows, but the code should.
