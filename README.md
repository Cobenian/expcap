ExPcap
======

A PCAP library written in Elixir. This does not wrap a C or Erlang PCAP library,
rather it attempts to be an idiomatic Elixir library.

## To Build

You must have Elixir 1.0.0+ installed along with mix.

    mix deps.get
    mix deps.compile
    mix compile
    mix escript.build

## To Run

Once the project has been built, the following escript can be run:

    ./expcap -f <path-file-pcap-file>

## Limitations

* Very few protocols are supported at this time.
