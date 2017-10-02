require "socket"
require "ipaddr"
require "openssl"
require "zlib"
require "pry"

local_server_ports = ["port-2", "port-2"]
server_ip = "my-server-ip-address"
server_ip = "127.0.0.1"
timeout = 5
package_size = 8 * 1024

handle_tcp =
  Proc.new do |sock, remote|
    fdset = [sock, remote]
    while true
      r, w, e = IO.select(fdset, [], [], timeout)

      break if r.nil?

      if r.include?(sock)
        begin
          sock_recv = sock.recvmsg.first
          if remote.sendmsg(sock_recv) <= 0
            break
          end
        rescue Exception => e
          puts e.backtrace
          break
        end
      end
      if r.include?(remote)
        begin
          remote_recv = remote.recvmsg(package_size).first
          if sock.sendmsg(remote_recv) <= 0
            break
          end
        rescue Exception => e
          puts e.backtrace
        end
      end
    end
  end

handle =
  Proc.new do |sock|
    data = sock.recvmsg.first
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
        # remote = Socket.new Socket::AF_INET, Socket::SOCK_STREAM
        # remote.connect Socket.pack_sockaddr_in(port, addr)
        remote = TCPSocket.new(addr, port)
        local_address = remote.local_address
        packed_address = [IPAddr.new("127.0.0.1").to_i.to_s(16)].pack("H*")
        packed_port = [local_address.ip_port.to_s(16).rjust(4, '0')].pack("H*")
        reply += packed_address + packed_port
        puts "Tcp connect to #{addr} #{port}"
      else
        e.backtrace
        reply = "\x05\x05\x00\x01"
      end
    rescue Exception => e
      puts e.backtrace
      reply = "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
    end
    sock.sendmsg(reply)
    handle_tcp.call(sock, remote) if reply[1] == "\x00" && mode == 1
    remote.close
  end

local_server_ports.each do |server_port|
  fork do
    server = TCPServer.new(server_ip, server_port)

    loop do
      client = server.accept
      thr = Thread.new do
        handle.call(client)
        client.close
      end

      puts Thread.list.size
    end
  end
end
