require "socket"
require 'openssl'
require 'pry'

# local_ip = 'my-local-ip-address'
# local_port = 'my-local-port'
# server_ip = 'my-server-ip-address'
# server_port = 'my-server-port'
local_ip = '127.0.0.1'
local_port = 2000
server_ip = '188.166.24.200'
server_port = 8499
key = "625bd76ee1934ad1b53f22c8d0222738"
iv = "c6f97771e3dfd066"
package_size = 8192

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
  Proc.new do |local_connection, remote_connection|
    fdset = [local_connection, remote_connection]
    counter = 0
    while true
      r, w, e = IO.select(fdset, [], [])

      if r.include?(local_connection)
        recv_data = local_connection.recvmsg.first
        if counter == 1
          begin
            addr = recv_data[5..-3]
            puts "Connecting #{addr}"
          rescue Exception => e
            nil
          end
        end
        counter += 1 if counter < 2
        break if remote_connection.sendmsg(encrypt_data.call(recv_data)) <= 0
      end

      if r.include?(remote_connection)
        data_length = remote_connection.recvmsg(2).first.unpack("H*").first.hex
        if data_length > 0
          remote_data = ""
          while (remote_data_length = remote_data.length) < data_length
            if remote_data_length == 0
              remote_data += remote_connection.recvmsg(data_length).first
            else
              remote_data += remote_connection.recvmsg(data_length - remote_data_length).first
            end
          end
          remote_data = decrypt_data.call(remote_data)
        else
          remote_data = ""
        end
        break if local_connection.sendmsg(remote_data) <= 0
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
