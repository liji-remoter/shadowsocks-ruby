require "socket"
require "ipaddr"
require "openssl"

ports = ["my-server-port"]
server = "my-server-ip-address" # This domain name was added into /etc/hosts on each server
ports = (8499..8508).to_a       # Multiple processes support
key = "625bd76ee1934ad1b53f22c8d0222738" # Openssl key
iv = "c6f97771e3dfd066"                  # Openssl iv
package_size = 4 * 1024                  # Data buffer size
timeout = 5                              # Timeout

encrypt_data =
  Proc.new do |plain_data|
    if plain_data.empty?
      plain_data
    else
      cipher = OpenSSL::Cipher::AES256.new(:CFB)
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      encrypted_data = cipher.update(plain_data) + cipher.final
      data_length = [encrypted_data.length.to_s(16).rjust(4, '0')].pack("H*")
      data_length + encrypted_data
    end
  end

decrypt_data =
  Proc.new do |encrypted_data|
    if encrypted_data.empty?
      encrypted_data
    else
      decipher = OpenSSL::Cipher::AES256.new(:CFB)
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv
      decipher.update(encrypted_data) + decipher.final
    end
  end

handle_tcp =
  Proc.new do |sock, remote|
    fdset = [sock, remote]
    while true
      r, w, e = IO.select(fdset, [], [], timeout)

      break if r.nil?
      if r.include?(sock)
        begin
          data_length = sock.recvmsg(2).first.unpack("H*").first.hex
          if data_length > 0
            recv_data = ""
            while (recev_data_length = recv_data.length) < data_length
              if recev_data_length == 0
                recv_data += sock.recvmsg(data_length).first
              else
                recv_data += sock.recvmsg(data_length - recev_data_length).first
              end
            end
            recv_data = decrypt_data.call(recv_data)
          else
            recv_data = ""
          end
          if remote.sendmsg(recv_data) <= 0
            break
          end
        rescue Exception => e
          puts e
        end
      end
      if r.include?(remote)
        begin
          x = remote.recvmsg(package_size).first
          if sock.sendmsg(encrypt_data.call(x)) <= 0
            break
          end
        rescue Exception => e
          puts e
        end
      end
    end
  end

handle =
  Proc.new do |sock|
    data_length = sock.recvmsg(2).first.unpack("H*").first.hex
    data = decrypt_data.call(sock.recvmsg(data_length).first)
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
        remote = TCPSocket.new(addr, port, Socket::AF_INET)
        local_address = remote.local_address
        packed_address = [IPAddr.new(local_address.ip_address).to_i.to_s(16)].pack("H*")
        packed_port = [local_address.ip_port.to_s(16).rjust(4, '0')].pack("H*")
        reply += packed_address + packed_port
        puts "Tcp connect to #{addr} #{port}"
      else
        reply = "\x05\x05\x00\x01"
      end
    rescue Exception => e
      reply = "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
    end
    sock.sendmsg(encrypt_data.call(reply))
    handle_tcp.call(sock, remote) if reply[1] == "\x00" && mode == 1
    remote.close
  end

ports.each do |port|
  fork do
    server = TCPServer.new(server, port)
    loop do
      client = server.accept
      thr = Thread.new do
        handle.call(client)
        client.close
      end
    end
  end
end
