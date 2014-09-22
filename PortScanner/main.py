'''
Port Scanner
'''
import optparse
import socket
#import threading
from socket import error as serr
#SLOCK = threading.Semaphore(1)
PORTSOPEN = {}
def format_ip(host, port):
    '''
    Format host port to:
    host:port
    '''
    return str(host) + ":" + str(port)

def connect(host, port):
    '''
    Connects to a specified host:port\
    '''
    print "[+] Connecting to target..."
    try:
        conn = socket.socket(socket.AF_INET, \
                             socket.SOCK_STREAM)
        conn.connect((host, port))
        print "[+] Connection established @ " + \
              format_ip(host, port)
        conn.send("0110\r\n")
        result = conn.recv(1024)
        #SLOCK.acquire()
        print "[+] TCP PORT " + str(port) + " " + \
              "OPEN:\n" + "--> " + str(result).split(";")[0]
        PORTSOPEN[port] = str(result).split(";")[0]
    except serr:
        #SLOCK.acquire()
        print "[-] [Error]: " + \
              "Connection Refused @ " + \
              format_ip(host, port)
    finally:
        #SLOCK.release()
        conn.close()

def port_scan(host, ports):
    '''
    Port Scan a specified host:port
    '''
    try:
        ipaddr = socket.gethostbyname(host)
    except serr:
        print "[-] Cannot Resolve: " + format_ip(host, ports)
        return
    try:
        ipname = socket.gethostbyaddr(ipaddr)
        print "[+] Scan Results for: " + ipname[0] + " " + ipaddr
    except serr:
        print "[+] Scan Results for: " + ipaddr
    socket.setdefaulttimeout(1)
    for port in ports.split(" "):
        print "[+] Port Scanning: " + format_ip(ipaddr, port)
        #thre = threading.Thread(target=connect,
        #                        args=(ipaddr, int(port)))
        #thre.start()
        connect(ipaddr, int(port))

if __name__ == "__main__":
    PARSER = optparse.OptionParser("Usage -H<Host> -P<Port>")
    PARSER.add_option("-H", dest="Tgthost", \
                      type="string", help="Specify Host")
    PARSER.add_option("-P", dest="Tgtport", \
                      type="string", help="Specify Port")
    (OPTIONS, ARGS) = PARSER.parse_args()
    TGTHOST = OPTIONS.Tgthost
    TGTPORT = OPTIONS.Tgtport
    if TGTHOST == None or TGTPORT == None:
        print PARSER.usage
        exit(0)
    port_scan(TGTHOST, TGTPORT)
    print PORTSOPEN
