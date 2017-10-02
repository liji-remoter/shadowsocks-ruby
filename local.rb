require "socket"
require 'openssl'
require 'geoip'

local_ip = 'my-local-ip-address'
local_port = 'my-local-port'
server_ips = ['server-1', 'server-2']
server_ports = ['server-port', 'server-port-2']
key = "625bd76ee1934ad1b53f22c8d0222738"
iv = "c6f97771e3dfd066"
timeout = 5
skip_country = 'China'          # Skip the connection if the destination in China
geoip = GeoIP.new('GeoIP.dat')  # fetch the country of the destination

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
    current_country = nil
    current_country_connection = nil
    while true
      r, w, e = IO.select(fdset, [], [], timeout)

      break if r.nil?
      if r.include?(local_connection)
        if counter == 0
          local_connection.recvmsg
          local_connection.sendmsg("\x05\x00")
          counter += 1 if counter < 2
          next
        end
        recv_data = local_connection.recvmsg.first

        if counter == 1
          begin
            addr = recv_data[5..-3]
            port = recv_data[-2,2].unpack("H*").first.hex
            current_country = geoip.country(addr).country_name
            puts "Connecting #{addr} #{port}"
            if current_country == skip_country
              current_country_connection = TCPSocket.new(local_ip, server_ports.sample)
              fdset << current_country_connection
            end
          rescue Exception => e
            puts e.backtrace
          end
        end
        counter += 1 if counter < 2
        begin
          if current_country == skip_country
            break if current_country_connection.sendmsg(recv_data) <= 0
          else
            break if remote_connection.sendmsg(encrypt_data.call(recv_data)) <= 0
          end
        rescue Exception => e
          e.backtrace
        end
      end

      if r.include?(current_country_connection)
        revc_data = current_country_connection.recvmsg.first
        if local_connection.sendmsg(revc_data) <= 0
          current_country_connection.close
          break
        end
        next
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

# Thread.start {
#   load "local_server.rb"
# }

Process.spawn "ruby local_server.rb"

server_ports.each do |server_port|
  fork do
    loop do
      begin
        remote_socket = TCPSocket.new(server_ips.sample, server_port)
        client = server.accept
        Thread.new {
          handle_tcp.call(client, remote_socket)
          client.close
          remote_socket.close
        }

      puts Thread.list.size
      rescue Exception => e
        puts e
      end
    end

  end
end


