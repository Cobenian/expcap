searchNodes=[{"doc":"This module represents a pcap file that has been parsed.","ref":"ExPcap.html","title":"ExPcap","type":"module"},{"doc":"Reads a file, parses the pcap contents and returns a list of the parsed packets.","ref":"ExPcap.html#from_file/1","title":"ExPcap.from_file/1","type":"function"},{"doc":"Parses the content of the packet according to the parser for this packet type. Then it recurses until the packet has been parsed completely. It may return something like an ethernet packet that contains an IPv4 packet that contains a UDP packet that contains a DNS packet.","ref":"ExPcap.html#parse_packet/2","title":"ExPcap.parse_packet/2","type":"function"},{"doc":"Parses the content of the packet according to the parser for this packet type. Then it recurses until the packet has been parsed completely. It may return something like an ethernet packet that contains an IPv4 packet that contains a UDP packet that contains a DNS packet.","ref":"ExPcap.html#parse_packet/3","title":"ExPcap.parse_packet/3","type":"function"},{"doc":"Reads a packet from the file and returns it or returns end of file if there is no data left to be read.","ref":"ExPcap.html#read_packet/2","title":"ExPcap.read_packet/2","type":"function"},{"doc":"Reads a packet from a file. This packet is then parsed and the result is returned.","ref":"ExPcap.html#read_packet/3","title":"ExPcap.read_packet/3","type":"function"},{"doc":"Reads all the packets from a file, parses them and returns a list of the parsed packets.","ref":"ExPcap.html#read_packets/3","title":"ExPcap.read_packets/3","type":"function"},{"doc":"Reads a pcap file and returns the parsed results.","ref":"ExPcap.html#read_pcap/1","title":"ExPcap.read_pcap/1","type":"function"},{"doc":"","ref":"ExPcap.html#t:t/0","title":"ExPcap.t/0","type":"type"},{"doc":"This module provides utility functions for dealing with binaries.","ref":"ExPcap.Binaries.html","title":"ExPcap.Binaries","type":"module"},{"doc":"Reverses the bytes in the binary. Examples iex&gt; ExPcap.Binaries . reverse_binary ( &lt;&lt; 1 , 2 , 3 , 4 &gt;&gt; ) &lt;&lt; 4 , 3 , 2 , 1 &gt;&gt;","ref":"ExPcap.Binaries.html#reverse_binary/1","title":"ExPcap.Binaries.reverse_binary/1","type":"function"},{"doc":"Reversed the contents of the first binary and prepends them to the second binary. This will recur until it reaches the degenerate case and returns the accumulator. Examples iex&gt; ExPcap.Binaries . reverse_binary ( &lt;&lt; 3 , 4 &gt;&gt; , &lt;&lt; 2 , 1 &gt;&gt; ) #&lt;&lt;3, 2, 1&gt;&gt; #and then &lt;&lt; 4 , 3 , 2 , 1 &gt;&gt;","ref":"ExPcap.Binaries.html#reverse_binary/2","title":"ExPcap.Binaries.reverse_binary/2","type":"function"},{"doc":"Converts a list of bytes to a binary. Ideally, this would be replaced by a standard elixir function, but I have not been able to find such a function in the standard library. Examples iex&gt; ExPcap.Binaries . to_binary ( [ 1 , 2 , 3 , 4 ] ) &lt;&lt; 1 , 2 , 3 , 4 &gt;&gt;","ref":"ExPcap.Binaries.html#to_binary/1","title":"ExPcap.Binaries.to_binary/1","type":"function"},{"doc":"Moves the contents of the list to the end of the binary. This will recur until it reaches the degenerate case and returns the accumulator (binary). Examples iex&gt; ExPcap.Binaries . to_binary ( [ 3 , 4 ] , &lt;&lt; 1 , 2 &gt;&gt; ) #&lt;&lt;1, 2, 3&gt;&gt; #and then &lt;&lt; 1 , 2 , 3 , 4 &gt;&gt;","ref":"ExPcap.Binaries.html#to_binary/2","title":"ExPcap.Binaries.to_binary/2","type":"function"},{"doc":"Converts a binary to a hex representation. This differs from 'Base.encode16' in that it adds the leading 0x prior to the hex value. Note that the return type could be cleaned up here to only include 0-9 and a-f but no need to do that right now. Examples iex&gt; ExPcap.Binaries . to_hex ( &lt;&lt; 255 , 0 &gt;&gt; ) &quot;0xFF00&quot;","ref":"ExPcap.Binaries.html#to_hex/1","title":"ExPcap.Binaries.to_hex/1","type":"function"},{"doc":"Converts the first 32 bits of the binary to a signed integer. Examples iex&gt; ExPcap.Binaries . to_int32 ( &lt;&lt; 255 , 255 , 255 , 255 &gt;&gt; ) - 1","ref":"ExPcap.Binaries.html#to_int32/1","title":"ExPcap.Binaries.to_int32/1","type":"function"},{"doc":"Converts a binary to a list of bytes. Examples iex&gt; ExPcap.Binaries . to_list ( &lt;&lt; 1 , 2 , 3 , 4 &gt;&gt; ) [ 1 , 2 , 3 , 4 ]","ref":"ExPcap.Binaries.html#to_list/1","title":"ExPcap.Binaries.to_list/1","type":"function"},{"doc":"Moves the bytes from the binary to the list. The order of the bytes will be reversed until the degenerate case is reached. This will recur until it reaches the degenerate case and returns the accumulator (list). Examples iex&gt; ExPcap.Binaries . to_list ( &lt;&lt; 3 , 4 &gt;&gt; , [ 2 , 1 ] ) #[3, 2, 1] #and then #[4, 3, 2, 1] #and then [ 1 , 2 , 3 , 4 ]","ref":"ExPcap.Binaries.html#to_list/2","title":"ExPcap.Binaries.to_list/2","type":"function"},{"doc":"Converts a binary to a 'raw' representation of the bytes. Examples iex&gt; ExPcap.Binaries . to_raw ( &lt;&lt; 1 , 2 , 3 , 4 &gt;&gt; ) #&lt;&lt;1, 2, 3, 4&gt;&gt; &quot;... redacted ...&quot;","ref":"ExPcap.Binaries.html#to_raw/1","title":"ExPcap.Binaries.to_raw/1","type":"function"},{"doc":"Converts a binary to a string that shows the bytes in the binary. The typical display of a binary truncates the bytes, the intent here was to show the entire contents of the binary. Examples iex&gt; ExPcap.Binaries . to_string ( &lt;&lt; 1 , 2 , 3 , 4 &gt;&gt; ) &quot;&lt;&lt;1, 2, 3, 4&gt;&gt;&quot;","ref":"ExPcap.Binaries.html#to_string/1","title":"ExPcap.Binaries.to_string/1","type":"function"},{"doc":"Converts the first 16 bits of the binary to an unsigned integer. Examples iex&gt; ExPcap.Binaries . to_uint16 ( &lt;&lt; 255 , 255 &gt;&gt; ) 65535","ref":"ExPcap.Binaries.html#to_uint16/1","title":"ExPcap.Binaries.to_uint16/1","type":"function"},{"doc":"Converts the first 32 bits of the binary to an unsigned integer. Examples iex&gt; ExPcap.Binaries . to_uint32 ( &lt;&lt; 255 , 255 , 255 , 255 &gt;&gt; ) 4294967295","ref":"ExPcap.Binaries.html#to_uint32/1","title":"ExPcap.Binaries.to_uint32/1","type":"function"},{"doc":"Converts the first 4 bits of the binary to an unsigned integer. Examples iex&gt; ExPcap.Binaries . to_uint4 ( &lt;&lt; 0xf :: size ( 4 ) &gt;&gt; ) 15","ref":"ExPcap.Binaries.html#to_uint4/1","title":"ExPcap.Binaries.to_uint4/1","type":"function"},{"doc":"Prints the contents of a PCAP file to stdout. The file may be specified with the --file or -f flag. If no flags are passed (or --help or -h) then the help is printed.","ref":"ExPcap.CLI.html","title":"ExPcap.CLI","type":"module"},{"doc":"The entry point, a.k.a. the main function.","ref":"ExPcap.CLI.html#main/1","title":"ExPcap.CLI.main/1","type":"function"},{"doc":"Parses the arguments which may be either: --help, -h :help --file, -f &lt;name&gt; [file: name]","ref":"ExPcap.CLI.html#parse_args/1","title":"ExPcap.CLI.parse_args/1","type":"function"},{"doc":"Prints the contents of the PCAP file in a somewhat human readable form.","ref":"ExPcap.CLI.html#process/1","title":"ExPcap.CLI.process/1","type":"function"},{"doc":"Parses the arguments and then either prints the contents of the PCAP file or prints the help message.","ref":"ExPcap.CLI.html#run/1","title":"ExPcap.CLI.run/1","type":"function"},{"doc":"This module represents the global header of a pcap file.","ref":"ExPcap.GlobalHeader.html","title":"ExPcap.GlobalHeader","type":"module"},{"doc":"Reads the pcap global header (the bits after the magic number) and returns a struct containing the global header values. The code reads the bytes according to the order specified by the magic header.","ref":"ExPcap.GlobalHeader.html#from_file/2","title":"ExPcap.GlobalHeader.from_file/2","type":"function"},{"doc":"Reads a global header from a binary containing a pcap header (after the magic number)","ref":"ExPcap.GlobalHeader.html#read_forward/2","title":"ExPcap.GlobalHeader.read_forward/2","type":"function"},{"doc":"Reads a global header from a binary containing a pcap header (after the magic number) but it does so by reading the bytes in reverse order for each value. The magic number indicates the byte order for reading.","ref":"ExPcap.GlobalHeader.html#read_reversed/2","title":"ExPcap.GlobalHeader.read_reversed/2","type":"function"},{"doc":"Returns true if the global header indicates that the bytes need to be reversed. Examples iex&gt; ExPcap.GlobalHeader . reverse_bytes? ( % ExPcap.GlobalHeader { magic_number : % ExPcap.MagicNumber { reverse_bytes : false } } ) false iex&gt; ExPcap.GlobalHeader . reverse_bytes? ( % ExPcap.GlobalHeader { magic_number : % ExPcap.MagicNumber { reverse_bytes : true } } ) true","ref":"ExPcap.GlobalHeader.html#reverse_bytes?/1","title":"ExPcap.GlobalHeader.reverse_bytes?/1","type":"function"},{"doc":"","ref":"ExPcap.GlobalHeader.html#t:t/0","title":"ExPcap.GlobalHeader.t/0","type":"type"},{"doc":"This module represents a 'magic number' from a pcap header. The magic number not only contains a known value, but the value indicates the order in which bytes should be read AND whether or not datetimes use milliseconds or nanoseconds.","ref":"ExPcap.MagicNumber.html","title":"ExPcap.MagicNumber","type":"module"},{"doc":"Returns the number of bytes contained in the magic number.","ref":"ExPcap.MagicNumber.html#bytes_in_magic/0","title":"ExPcap.MagicNumber.bytes_in_magic/0","type":"function"},{"doc":"Reads the magic number from the file passed in.","ref":"ExPcap.MagicNumber.html#from_file/1","title":"ExPcap.MagicNumber.from_file/1","type":"function"},{"doc":"Returns a magic number that indicates that the bytes need to be reversed when read and that datetimes are in nanoseconds.","ref":"ExPcap.MagicNumber.html#magic_number/4","title":"ExPcap.MagicNumber.magic_number/4","type":"function"},{"doc":"This reads the bytes of the magic number and matches them with the appropriate interpretation of the magic number.","ref":"ExPcap.MagicNumber.html#read_magic/1","title":"ExPcap.MagicNumber.read_magic/1","type":"function"},{"doc":"","ref":"ExPcap.MagicNumber.html#t:t/0","title":"ExPcap.MagicNumber.t/0","type":"type"},{"doc":"This module contains information about the types of packets that are contained in the PCAP file. For example, if the network type is 'ethernet' then each packet in the pcap file will be an ethernet packet.","ref":"ExPcap.NetworkTypes.html","title":"ExPcap.NetworkTypes","type":"module"},{"doc":"Returns the type of packets that this pcap file contains in a human readable format.","ref":"ExPcap.NetworkTypes.html#network_name/1","title":"ExPcap.NetworkTypes.network_name/1","type":"function"},{"doc":"This module represents a single pcap packet. It contains a header and both raw and parsed versions of the body.","ref":"ExPcap.Packet.html","title":"ExPcap.Packet","type":"module"},{"doc":"","ref":"ExPcap.Packet.html#t:t/0","title":"ExPcap.Packet.t/0","type":"type"},{"doc":"This module represents the body of a packet.","ref":"ExPcap.PacketData.html","title":"ExPcap.PacketData","type":"module"},{"doc":"Reads the packet body from the file.","ref":"ExPcap.PacketData.html#from_file/3","title":"ExPcap.PacketData.from_file/3","type":"function"},{"doc":"This function reads the body of a packet.","ref":"ExPcap.PacketData.html#read_forward/2","title":"ExPcap.PacketData.read_forward/2","type":"function"},{"doc":"This function reads the body of a packet reversing the bytes along the way.","ref":"ExPcap.PacketData.html#read_reversed/2","title":"ExPcap.PacketData.read_reversed/2","type":"function"},{"doc":"","ref":"ExPcap.PacketData.html#t:t/0","title":"ExPcap.PacketData.t/0","type":"type"},{"doc":"This module represents a pcap packet header.","ref":"ExPcap.PacketHeader.html","title":"ExPcap.PacketHeader","type":"module"},{"doc":"Reads a pcap packet header from the file.","ref":"ExPcap.PacketHeader.html#from_file/2","title":"ExPcap.PacketHeader.from_file/2","type":"function"},{"doc":"Reads a packet header from the binary passed in.","ref":"ExPcap.PacketHeader.html#read_forward/1","title":"ExPcap.PacketHeader.read_forward/1","type":"function"},{"doc":"Reads a packet header from the binary passed in, in rerverse byte order.","ref":"ExPcap.PacketHeader.html#read_reversed/1","title":"ExPcap.PacketHeader.read_reversed/1","type":"function"},{"doc":"","ref":"ExPcap.PacketHeader.html#t:t/0","title":"ExPcap.PacketHeader.t/0","type":"type"},{"doc":"This protocol indicates a module that is aware of how to convert binary data to a parsed packet.","ref":"PayloadParser.html","title":"PayloadParser","type":"protocol"},{"doc":"Parses the body of a packet into a new packet (presumably of another protocol) For example a UDP packet body may contain a DNS packet.","ref":"PayloadParser.html#from_data/1","title":"PayloadParser.from_data/1","type":"function"},{"doc":"","ref":"PayloadParser.html#t:t/0","title":"PayloadParser.t/0","type":"type"},{"doc":"This protocol indicates a module that is aware of which parser should be used to handle its body.","ref":"PayloadType.html","title":"PayloadType","type":"protocol"},{"doc":"This function is passed a packet and it returns the parser that should be used to parse its body.","ref":"PayloadType.html#payload_parser/1","title":"PayloadType.payload_parser/1","type":"function"},{"doc":"","ref":"PayloadType.html#t:t/0","title":"PayloadType.t/0","type":"type"},{"doc":"A parsed DNS packet","ref":"Protocol.Dns.html","title":"Protocol.Dns","type":"module"},{"doc":"Returns a parsed DNS packet","ref":"Protocol.Dns.html#from_data/1","title":"Protocol.Dns.from_data/1","type":"function"},{"doc":"Parses a DNS header","ref":"Protocol.Dns.html#header/1","title":"Protocol.Dns.header/1","type":"function"},{"doc":"","ref":"Protocol.Dns.html#t:t/0","title":"Protocol.Dns.t/0","type":"type"},{"doc":"A parsed DNS packet header","ref":"Protocol.Dns.Header.html","title":"Protocol.Dns.Header","type":"module"},{"doc":"Is this response authoritative?","ref":"Protocol.Dns.Header.html#aa_name/1","title":"Protocol.Dns.Header.aa_name/1","type":"function"},{"doc":"What is the op code of this DNS packet?","ref":"Protocol.Dns.Header.html#opcode_name/1","title":"Protocol.Dns.Header.opcode_name/1","type":"function"},{"doc":"Is this a query or a response?","ref":"Protocol.Dns.Header.html#qr_name/1","title":"Protocol.Dns.Header.qr_name/1","type":"function"},{"doc":"Is recursion available?","ref":"Protocol.Dns.Header.html#ra_name/1","title":"Protocol.Dns.Header.ra_name/1","type":"function"},{"doc":"What is the r code of this DNS packet?","ref":"Protocol.Dns.Header.html#rcode_name/1","title":"Protocol.Dns.Header.rcode_name/1","type":"function"},{"doc":"Is recursion desired?","ref":"Protocol.Dns.Header.html#rd_name/1","title":"Protocol.Dns.Header.rd_name/1","type":"function"},{"doc":"Is this response truncated?","ref":"Protocol.Dns.Header.html#tc_name/1","title":"Protocol.Dns.Header.tc_name/1","type":"function"},{"doc":"The first bit is reserved. The second bit indciates if the response was authenticated or not. The third bit indciates if the data was authenticated or not.","ref":"Protocol.Dns.Header.html#z_name/1","title":"Protocol.Dns.Header.z_name/1","type":"function"},{"doc":"","ref":"Protocol.Dns.Header.html#t:t/0","title":"Protocol.Dns.Header.t/0","type":"type"},{"doc":"A parsed DNS question","ref":"Protocol.Dns.Question.html","title":"Protocol.Dns.Question","type":"module"},{"doc":"","ref":"Protocol.Dns.Question.html#t:t/0","title":"Protocol.Dns.Question.t/0","type":"type"},{"doc":"A parsed DNS resource record","ref":"Protocol.Dns.ResourceRecord.html","title":"Protocol.Dns.ResourceRecord","type":"module"},{"doc":"The dclass name of this packet","ref":"Protocol.Dns.ResourceRecord.html#class_name/1","title":"Protocol.Dns.ResourceRecord.class_name/1","type":"function"},{"doc":"Prints rdata to a human readable string. Very few rr types are supported.","ref":"Protocol.Dns.ResourceRecord.html#rdata_string/1","title":"Protocol.Dns.ResourceRecord.rdata_string/1","type":"function"},{"doc":"Reads an answer from the 'data' and returns a tuple of the resource record and remaining bytes.","ref":"Protocol.Dns.ResourceRecord.html#read_answer/2","title":"Protocol.Dns.ResourceRecord.read_answer/2","type":"function"},{"doc":"Returns a list of the answers (resource records) in this section of the DNS packet. The section may be the answer, authoritative or additional sections, this code is generic so it doesn't care which section is being read.","ref":"Protocol.Dns.ResourceRecord.html#read_answers/3","title":"Protocol.Dns.ResourceRecord.read_answers/3","type":"function"},{"doc":"Returns a list of the answers (resource records) in this section of the DNS packet. The section may be the answer, authoritative or additional sections, this code is generic so it doesn't care which section is being read.","ref":"Protocol.Dns.ResourceRecord.html#read_answers/4","title":"Protocol.Dns.ResourceRecord.read_answers/4","type":"function"},{"doc":"Reads the 'len' number of bytes from the binary and returns a tuple of the bytes read the remaining bytes.","ref":"Protocol.Dns.ResourceRecord.html#read_bytes/2","title":"Protocol.Dns.ResourceRecord.read_bytes/2","type":"function"},{"doc":"Returns the list of questions in the DNS packet and answer, authoritative and additional sections. Finally, the tuple returned contains the remaining bytes if there are any.","ref":"Protocol.Dns.ResourceRecord.html#read_dns/3","title":"Protocol.Dns.ResourceRecord.read_dns/3","type":"function"},{"doc":"Reads a label (such as 'ns1.google.com'). It technically reads one label at a time and recurs until the end of the label is reached.","ref":"Protocol.Dns.ResourceRecord.html#read_label/4","title":"Protocol.Dns.ResourceRecord.read_label/4","type":"function"},{"doc":"Reads a name from the data and returns a tuple of the name read and the reamining bytes that have not been read yet.","ref":"Protocol.Dns.ResourceRecord.html#read_name/2","title":"Protocol.Dns.ResourceRecord.read_name/2","type":"function"},{"doc":"Reads a name (label or offset) from the data and returns a tuple with the name read and the remaining bytes not yet read.","ref":"Protocol.Dns.ResourceRecord.html#read_name/4","title":"Protocol.Dns.ResourceRecord.read_name/4","type":"function"},{"doc":"Reads the offset position and then returns the label at the offset in the entire 'message'. Returns a tuple of the label read and the remaining bytes not yet read.","ref":"Protocol.Dns.ResourceRecord.html#read_offset/3","title":"Protocol.Dns.ResourceRecord.read_offset/3","type":"function"},{"doc":"Reads a DNS question from the 'data'. Returns a tuple of the question and the remaining bytes.","ref":"Protocol.Dns.ResourceRecord.html#read_question/2","title":"Protocol.Dns.ResourceRecord.read_question/2","type":"function"},{"doc":"Returns a tuple with the list of the questions in this DNS packet and a binary of the remaining bytes that have not yet been read.","ref":"Protocol.Dns.ResourceRecord.html#read_questions/3","title":"Protocol.Dns.ResourceRecord.read_questions/3","type":"function"},{"doc":"Returns a tuple with the list of the questions in this DNS packet and a binary of the remaining bytes that have not yet been read.","ref":"Protocol.Dns.ResourceRecord.html#read_questions/4","title":"Protocol.Dns.ResourceRecord.read_questions/4","type":"function"},{"doc":"The rr type","ref":"Protocol.Dns.ResourceRecord.html#type_name/1","title":"Protocol.Dns.ResourceRecord.type_name/1","type":"function"},{"doc":"","ref":"Protocol.Dns.ResourceRecord.html#t:t/0","title":"Protocol.Dns.ResourceRecord.t/0","type":"type"},{"doc":"A parsed ethernet packet","ref":"Protocol.Ethernet.html","title":"Protocol.Ethernet","type":"module"},{"doc":"Returns a parsed ethernet packet.","ref":"Protocol.Ethernet.html#from_data/1","title":"Protocol.Ethernet.from_data/1","type":"function"},{"doc":"Returns a parsed ethernet header from an ethernet packet.","ref":"Protocol.Ethernet.html#header/1","title":"Protocol.Ethernet.header/1","type":"function"},{"doc":"","ref":"Protocol.Ethernet.html#t:t/0","title":"Protocol.Ethernet.t/0","type":"type"},{"doc":"A parsed ethernet packet header","ref":"Protocol.Ethernet.Header.html","title":"Protocol.Ethernet.Header","type":"module"},{"doc":"","ref":"Protocol.Ethernet.Header.html#t:t/0","title":"Protocol.Ethernet.Header.t/0","type":"type"},{"doc":"This module contains functions related to the payload types that this ethernet packet may contain.","ref":"Protocol.Ethernet.Types.html","title":"Protocol.Ethernet.Types","type":"module"},{"doc":"Prints the appropriate human readable ethernet type for the wire format.","ref":"Protocol.Ethernet.Types.html#ethernet_type_name/1","title":"Protocol.Ethernet.Types.ethernet_type_name/1","type":"function"},{"doc":"A parsed IPv4 packet.","ref":"Protocol.Ipv4.html","title":"Protocol.Ipv4","type":"module"},{"doc":"Parses an IPv4 packet and returns it","ref":"Protocol.Ipv4.html#from_data/1","title":"Protocol.Ipv4.from_data/1","type":"function"},{"doc":"Parses an IPv4Header","ref":"Protocol.Ipv4.html#header/1","title":"Protocol.Ipv4.header/1","type":"function"},{"doc":"","ref":"Protocol.Ipv4.html#t:t/0","title":"Protocol.Ipv4.t/0","type":"type"},{"doc":"A parsed IPv4 packet header","ref":"Protocol.Ipv4.Header.html","title":"Protocol.Ipv4.Header","type":"module"},{"doc":"","ref":"Protocol.Ipv4.Header.html#t:t/0","title":"Protocol.Ipv4.Header.t/0","type":"type"},{"doc":"A parsed UDP packet","ref":"Protocol.Udp.html","title":"Protocol.Udp","type":"module"},{"doc":"Returns a parsed UDP packet","ref":"Protocol.Udp.html#from_data/1","title":"Protocol.Udp.from_data/1","type":"function"},{"doc":"Parses the header of a UDP packet","ref":"Protocol.Udp.html#header/1","title":"Protocol.Udp.header/1","type":"function"},{"doc":"","ref":"Protocol.Udp.html#t:t/0","title":"Protocol.Udp.t/0","type":"type"},{"doc":"A parsed UDP packet header","ref":"Protocol.Udp.Header.html","title":"Protocol.Udp.Header","type":"module"},{"doc":"","ref":"Protocol.Udp.Header.html#t:t/0","title":"Protocol.Udp.Header.t/0","type":"type"}]