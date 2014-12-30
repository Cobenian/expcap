# GlobalHeader.read_file("/tmp/dns.cap") |> GlobalHeader.read |> IO.inspect

f = File.open!("/tmp/dns.cap")
ExPcap.GlobalHeader.from_file(f) |> IO.inspect
ExPcap.PacketHeader.from_file(f, true) |> IO.inspect
IO.binread(f, 70) |> ExPcap.Binaries.reverse_binary |> String.codepoints |> IO.inspect
File.close(f)
