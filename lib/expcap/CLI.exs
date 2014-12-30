# GlobalHeader.read_file("/tmp/dns.cap") |> GlobalHeader.read |> IO.inspect

f = File.open!("/tmp/dns.cap")
magic_number = ExPcap.MagicNumber.from_file(f)
magic_number |> IO.inspect
ExPcap.GlobalHeader.from_file(f, magic_number) |> IO.inspect
ExPcap.PacketHeader.from_file(f, magic_number) |> IO.inspect
IO.binread(f, 70) |> ExPcap.Binaries.reverse_binary |> String.codepoints |> IO.inspect
File.close(f)
