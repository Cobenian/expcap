defmodule ExPcap.DocTest do
  use ExUnit.Case

  doctest ExPcap.CLI
  doctest ExPcap.Binaries
  doctest ExPcap.GlobalHeader
  doctest ExPcap.MagicNumber
  doctest ExPcap.Packet
  doctest ExPcap.PacketData
  doctest ExPcap.PacketHeader
end
