require "socket"
require "pry"

local_ip = '127.0.0.1'
local_port = '1080'
server_ip = '192.168.1.5'
server_port = '8499'

handle_tcp =
  Proc.new do |sock, remote|
    fdset = [sock, remote]
    counter = 0
    while true
      r, w, e = IO.select([sock, remote], [], [])

      if r.include?(sock)
        r_data = sock.recv(4096)
        if counter == 1
          begin
            addr = r_data[4..-3]
            puts "Connecting #{addr}"
          rescue Exception => e
            nil
          end
        end
        counter += 1 if counter < 2
        break if remote.send(r_data, 0) <= 0
      end

      if r.include?(remote)
        data = remote.recv(4096)
        break if sock.send(data, 0) <= 0
      end
    end
  end

server = TCPServer.new(local_ip, local_port)
loop do
  begin
    remote_socket = TCPSocket.new(server_ip, server_port)
    client = server.accept
    Thread.new {
      handle_tcp.call(client, remote_socket)
      client.close
      remote_socket.close
    }
  rescue Exception => e
    puts e
  end
end
