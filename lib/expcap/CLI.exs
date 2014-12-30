# GlobalHeader.read_file("/tmp/dns.cap") |> GlobalHeader.read |> IO.inspect

f = File.open!("/tmp/dns.cap")
magic_number = ExPcap.MagicNumber.from_file(f)
magic_number |> IO.inspect
global_header = ExPcap.GlobalHeader.from_file(f, magic_number)
global_header |> IO.inspect
packet_header = ExPcap.PacketHeader.from_file(f, magic_number)
packet_header |> IO.inspect
packet_data = ExPcap.PacketData.from_file(f, packet_header)
packet_data |> IO.inspect
File.close(f)
