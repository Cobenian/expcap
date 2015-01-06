ExPcap
======

A PCAP library written in Elixir. This does not wrap a C or Erlang PCAP library,
rather it attempts to be an idiomatic Elixir library.

This library parses pcap files, however it does not yet support most protocols
that can be contained within a pcap file. The only supported protocols at the
moment are:

* Ethernet
* IPv4
* UDP
* DNS

## To Build Documentation

You must have run mix deps.get and mix deps.compile first.

    mix docs

## To Build

You must have Elixir 1.0.0+ installed along with mix.

    mix deps.get
    mix deps.compile
    mix compile
    mix escript.build

## To Test

You must have run mix deps.get and mix deps.compile first.

    mix test

## To Run

Once the project has been built, the following escript can be run:

    ./expcap -f <path-file-pcap-file>

A sample DNS cap file can be found in test/data/dns.cap. This file is provided
by Wireshark as a sample capture.

    ./expcap -f test/data/dns.cap

### Windows

Escript does not run on Windows so the expcap escript will not work. However,
the code in this library should work on Windows if used as an Elixir library.

## Limitations

* Very few protocols are supported at this time.
* Well formed pcap files can be parsed properly, however corrupted pcap files
may not have helpful error messages.
