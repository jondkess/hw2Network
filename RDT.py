import Network
import argparse
from time import sleep
import hashlib
import time


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 22
    length_length = 10
    type_length = 2
    ## length of md5 checksum in hex
    checksum_length = 32
    ack_nak = 00
    seq_num = 0
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        #extract the fields
        self.seq_num = int(byte_S[Packet.length_length + Packet.type_length : Packet.type_length+Packet.length_length+Packet.seq_num_S_length])
        ack_nak = int(byte_S[:Packet.type_length])    #get whether ack or nak
        msg_S = byte_S[Packet.type_length+Packet.length_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(self.seq_num, msg_S, ack_nak)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        type_S = str(self.ack_nak).zfill(self.type_length)
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_length bytes
        length_S = str(self.type_length + self.length_length + self.seq_num_S_length + self.checksum_length + len(self.msg_S)).zfill(self.length_length)
        #compute the checksum
        checksum = hashlib.md5((type_S+length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return type_S + length_S + seq_num_S + checksum_S + self.msg_S
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields\
        type_S = byte_S[:Packet.type_length]
        length_S = byte_S[Packet.type_length:Packet.type_length + Packet.length_length]
        seq_num_S = byte_S[Packet.type_length + Packet.length_length : Packet.type_length + Packet.length_length + Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.type_length + Packet.length_length+Packet.seq_num_S_length : Packet.type_length + Packet.seq_num_S_length+Packet.length_length+Packet.checksum_length]
        msg_S = byte_S[Packet.type_length + Packet.length_length+Packet.seq_num_S_length+Packet.checksum_length : int(length_S)]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(type_S+length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

class PacketRDT21(Packet):

     def __init__(self, seq_num, msg_S, ack_nak):
        Packet.__init__(self, seq_num, msg_S)
        self.ack_nak = ack_nak

     def is_ack(value):
        if(value is 10):
            return True
        return False

     def is_nak(value):
        if(value is 11):
            return True
        return False


class RDT:
    ## latest sequence number used in a packet
    rec_seq = 0
    send_seq = 0
    seq_number = 1
    ## buffer of bytes read from network
    byte_buffer = ''
    dict = {}
    dataPacket = PacketRDT21(0, '', 00)
    timer = 0
    waiting = False
    


    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
    
    def rdt_2_1_send(self, msg_S, ack_nak=00, resend=False):
        self.seq_number += 1
        if ack_nak == 11:
            p = PacketRDT21(send_seq_num, msg_S, ack_nak)
        elif send_seq_num == 0:    
            p = PacketRDT21(self.seq_number, msg_S, ack_nak) 
            if ack_nak == 00:
                self.timer = time.time()
                self.dataPacket = p
                self.waiting = True
            self.dict[self.seq_number] = p
        elif send_seq_num == 1:
            last = self.dict.keys()[-1]
            p = self.dict[last]
        else:
            p = self.dict[send_seq_num]
            if p.ack_nak == 00:
                self.timer = time.time()
                self.dataPacket = p
                self.waiting = True

        self.network.udt_send(p.get_byte_S())

    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            if (self.timer + 1 < time.time() and self.waiting):
                self.rdt_3_0_send(self.dataPacket.msg_S, self.dataPacket.seq_num, 00)
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.type_length + Packet.length_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[Packet.type_length:Packet.type_length + Packet.length_length])
            if len(self.byte_buffer) < length:
                #sleep(0.5)
                return ret_S #not enough bytes to read the whole packet
            try:
                p = PacketRDT21.from_byte_S(self.byte_buffer[0:length])

                if(PacketRDT21.is_ack(p.ack_nak)):
                    if(PacketRDT21.corrupt(self.byte_buffer)):
                        self.rdt_3_0_send("", p.seq_num, 11)
                    self.timer = time.time()
                    ret_S = None
                elif(PacketRDT21.is_nak(p.ack_nak)):   #if nak
                    self.rdt_3_0_send("", p.seq_num, 00)
                    self.timer = time.time()
                    ret_S = None
                #check the checksum and send nak if corrupt
                elif(PacketRDT21.corrupt(self.byte_buffer)):
                    self.rdt_3_0_send("", p.seq_num, 11)
                    self.time = time.time()
                    ret_S = None
                else:
                    self.rdt_3_0_send("", 0, 10)
                    ret_S = p.msg_S
                    self.waiting = False
                    self.time = time.time()
            except:
                self.rdt_3_0_send("", 1, 11)
                ret_S = None
                self.time = time.time()
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration

    def rdt_3_0_send(self, msg_S, send_seq_num=0, ack_nak=00):
        self.seq_number += 1
        if ack_nak == 11:
            p = PacketRDT21(send_seq_num, msg_S, ack_nak)
        elif send_seq_num == 0:    
            p = PacketRDT21(self.seq_number, msg_S, ack_nak) 
            if ack_nak == 00:
                self.timer = time.time()
                self.dataPacket = p
                self.waiting = True
            self.dict[self.seq_number] = p
        elif send_seq_num == 1:
            last = self.dict.keys()[-1]
            p = self.dict[last]
        else:
            p = self.dict[send_seq_num]
            if p.ack_nak == 00:
                self.timer = time.time()
                self.dataPacket = p
                self.waiting = True

        self.network.udt_send(p.get_byte_S())
        
    def rdt_3_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            if (self.timer + 1 < time.time() and self.waiting):
                self.rdt_3_0_send(self.dataPacket.msg_S, self.dataPacket.seq_num, 00)
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.type_length + Packet.length_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[Packet.type_length:Packet.type_length + Packet.length_length])
            if len(self.byte_buffer) < length:
                #sleep(0.5)
                return ret_S #not enough bytes to read the whole packet
            try:
                p = PacketRDT21.from_byte_S(self.byte_buffer[0:length])

                if(PacketRDT21.is_ack(p.ack_nak)):
                    if(PacketRDT21.corrupt(self.byte_buffer)):
                        self.rdt_3_0_send("", p.seq_num, 11)
                    self.timer = time.time()
                    ret_S = None
                elif(PacketRDT21.is_nak(p.ack_nak)):   #if nak
                    self.rdt_3_0_send("", p.seq_num, 00)
                    self.timer = time.time()
                    ret_S = None
                #check the checksum and send nak if corrupt
                elif(PacketRDT21.corrupt(self.byte_buffer)):
                    self.rdt_3_0_send("", p.seq_num, 11)
                    self.time = time.time()
                    ret_S = None
                else:
                    self.rdt_3_0_send("", 0, 10)
                    ret_S = p.msg_S
                    self.waiting = False
                    self.time = time.time()
            except:
                self.rdt_3_0_send("", 1, 11)
                ret_S = None
                self.time = time.time()
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        