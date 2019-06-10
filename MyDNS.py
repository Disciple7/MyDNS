import socket
import socketserver
import struct

namemap = {}

class  DNSServer:
    def __init__(self):
        self.port = 53
        self.author_ip_port = ("114.114.114.114",53)
        with open(r'dnsrelay.txt', 'r') as dns_list:  # 打开列表文件
            while True:
                each_line = dns_list.readline()  # 读取每行文件
                if not each_line:  # 读取到空时结束读取
                    break
                else:
                    ip, domain_name = each_line.split(' ', 1)  # 把每行拆分为ip和域名
                    domain_name = domain_name.strip('\n')  # 去掉域名里的换行符
                    print(ip, domain_name)  # 调试时，打印域名列表，确认读取成功
                    namemap[domain_name] = ip
        # print(namemap)
    def start(self):
        server = socketserver.ThreadingUDPServer(("",self.port),DNSUDPHandler)  # 使用多线程模式处理UDP数据
        server.serve_forever()  # 开始运行

class DNSHeader:
    def __init__(self,client_id,flags,QDCount,ANCount,NSCount,ARCount):
        self.client_id = client_id
        # ID为验证ID，请求包和应答包要保持一致
        self.flags = flags
        # flags例： 33152对应二进制的1 0000 0 0 1 1 000 0000，代表这是“响应报，标准查询，非权威答案，非截断，期望递归，递归可用，Z（保留字段），没有差错”
        # 收到的查询包通常是256，即 0 0000 0 0 1 0 000 0000
        # 最后一个是RCode，RCode = 3 时表示没有这个域名。
        self.QDcount = QDCount
        # QDcount通常为1，表示有1个QSF
        self.ANCount = ANCount
        self.NSCount = NSCount
        self.ARCount = ARCount
    def pack(self):
        header = struct.pack('>HHHHHH', self.client_id, self.flags, self.QDcount, self.ANCount, self.NSCount, self.ARCount)
        # print(header)
        return header

class DNS_QSF:
    def __init__(self,QName,QType,QClass):
        self.QName = QName  # QName为字符串，是查询的域名。
        self.QType = QType  # QType和QClass是一个short
        self.QClass = QClass
    def pack(self):
        labels = self.QName.split('.')
        raw_QName = ''
        for label in labels:
            label_len = len(label)
            raw_QName += chr(label_len)
            raw_QName += label
        raw_QName += chr(0)  # encode函数能把字符串编码成网络传输用的字节码。对于英文字节码来说可以不选择编码方式，含有其他字符则要选择，如GBK，Unicode或UTF8
        raw_QSF = raw_QName.encode() + struct.pack('>HH',self.QType,self.QClass)
        return raw_QSF
        # print(self.raw_QSF)



class DNS_RRS:
    def __init__(self,Name,Type,Class,TTL,RDLength,RData):
        self.Name = Name
        self.Type = Type
        self.Class = Class
        self.TTL = TTL
        self.RDLength = RDLength
        self.RData = RData
    def pack(self):
        RRS = struct.pack('>HHHLH',self.Name,self.Type,self.Class,self.TTL,self.RDLength)
        ip_split = self.RData.split('.')
        for s in ip_split:
            RRS = RRS + struct.pack('B',int(s))  # DNS查询中，IP是4个小于256的int值，以chr(int)的形式打包。
        # print(RRS)
        return RRS


class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # 获取包、套接字
        raw_packet = self.request[0].strip()
        socket_server = self.request[1]
        # 解析Header
        raw_header = raw_packet[0:12]
        header_unpack = struct.unpack(">HHHHHH", raw_header)  # 切片操作：取索引0到i+1，但不包括i+1
        header = DNSHeader(header_unpack[0],header_unpack[1],header_unpack[2],header_unpack[3],header_unpack[4],header_unpack[5])
        #　print(header_unpack)
        # 解析QSF
        raw_QSF = raw_packet[12:]
        QName = ''
        i = 1
        while True:
            d = raw_QSF[i]
            if d == 0:
                break
            if d < 32:  # 这个意思是字节串前面的数字，它是一个字符，但是它的ASCII码等于数字。当读到这个的时候直接加一个'.'
                QName += '.'
            else:
                QName += chr(d)
            i = i + 1
        QType,QClass = struct.unpack('>HH',raw_QSF[i+1:i+5])
        QSF = DNS_QSF(QName,int(QType),int(QClass))
        # print(QName,QType,QClass)
        # 查询列表，根据相应的情况构造应答包并发回
        # 没有处理IPv6的地址请求（QType = 28），一律做了转发
        if QType == 1 and QClass == 1 and namemap.__contains__(QName):
            if namemap[QName]=='0.0.0.0':  # 屏蔽功能：33155对应二进制的1 0000 0 0 1 1 000 0003，代表这是“响应报，标准查询，非权威答案，非截断，期望递归，递归可用，Z（保留字段），没有此域名”
                print(QName+',Blocked')
                nop_header = DNSHeader(header.client_id,33155,1,0,0,0)
                nop_QSF = QSF
                socket_server.sendto(nop_header.pack()+ nop_QSF.pack(),self.client_address)
            else :  # 查询功能
                print(QName+',Answered')
                ans_header = DNSHeader(header.client_id,33152,1,1,0,0)
                ans_QSF = QSF
                ans_RRS = DNS_RRS(Name = 0xc00c,Type = 1,Class = 1,TTL = 445,RDLength = 4,RData = namemap[QName])
                socket_server.sendto(ans_header.pack()+ans_QSF.pack()+ans_RRS.pack(),self.client_address)
        else:  # 转发功能。注：权威应答不是随便填就能权威应答的。这里只是做转发，不要填NSCount和AUTHOR_RRS
            # 转发功能可以使用了。
            print(QName+',Transported')
            socket_author = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            socket_author.sendto(raw_packet,('114.114.114.114',53))
            author_data,author_addr = socket_author.recvfrom(1024)
            raw_author_header = author_data[0:12]
            author_header_unpack = struct.unpack(">HHHHHH",raw_author_header)
            author_header = DNSHeader(header.client_id,author_header_unpack[1],author_header_unpack[2],author_header_unpack[3],author_header_unpack[4],author_header_unpack[5])
            raw_author_QSF_RRS = author_data[12:]
            socket_server.sendto(author_header.pack()+raw_author_QSF_RRS,self.client_address)
            # print(author_data,author_addr)


if  __name__ == "__main__":
    MyServer = DNSServer()
    MyServer.start()