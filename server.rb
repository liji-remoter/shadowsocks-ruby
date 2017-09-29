require "socket"
require "ipaddr"
require 'pry'

port = "8499"
server = "192.168.1.5"

handle_tcp =
  Proc.new do |sock, remote|
    fdset = [sock, remote]

    while true
      r, w, e = IO.select([sock, remote], [], [])
      r.include?(sock) && remote.send(sock.recv(4096), 0) <= 0 && break
      r.include?(remote) && sock.send(remote.recv(4096), 0) <= 0 && break
    end
  end

handle =
  Proc.new do |sock|
    x = sock.recv(4096)
    puts x.unpack("H*")
    sock.send("\x05\x00", 0)
    data = sock.recv(4096)
    mode = data[1].unpack("H*").first.hex
    addrtype = data[3].unpack("H*").first.hex
    if addrtype == 1
      addr = IPAddr.new(data[5..-3]).to_s
    elsif addrtype == 3
      addr = data[5..-3]
    else
      return
    end

    port = data[-2,2].unpack("H*").first.hex
    reply = "\x05\x00\x00\x01"

    begin
      if mode == 1
        remote = TCPSocket.new(addr, port)
        local_address = remote.local_address
        packed_address = [IPAddr.new(local_address.ip_address).to_i.to_s(16)].pack("H*")
        packed_port = [local_address.ip_port.to_s(16).rjust(4, '0')].pack("H*")
        reply += packed_address + packed_port
        puts "Tcp connect to #{addr} #{port}"
      else
        reply = "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
      end
      sock.send(reply, 0)
      handle_tcp.call(sock, remote) if reply[1] == "\x00" && mode == 1
      remote.close
    rescue Exception => e
      puts e.backtrace
    end
  end

server = TCPServer.new(server, port)

loop do
  client = server.accept
  Thread.new {
    handle.call(client)
    client.close
  }
end
