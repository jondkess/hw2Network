import Network
import argparse
from time import sleep
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    type_length = 2
    ## length of md5 checksum in hex
    checksum_length = 32
    ack_nak = 00
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
#        if Packet.corrupt(byte_S):
#            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length + Packet.type_length : Packet.type_length+Packet.length_S_length+Packet.seq_num_S_length])
        ack_nak = int(byte_S[:Packet.type_length])    #get whether ack or nak
        msg_S = byte_S[Packet.type_length+Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S, ack_nak)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        type_S = str(self.ack_nak).zfill(self.type_length)
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.type_length + self.length_S_length + self.seq_num_S_length + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((type_S+length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return type_S + length_S + seq_num_S + checksum_S + self.msg_S
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields\
        type_S = byte_S[:Packet.type_length]
        length_S = byte_S[Packet.type_length:Packet.type_length + Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length + Packet.type_length : Packet.type_length + Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.type_length + Packet.length_S_length+Packet.seq_num_S_length : Packet.type_length + Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.type_length + Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length : int(length_S)]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(type_S+length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

class PacketRDT21(Packet):
     #last_packet = ''

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
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''
    ## state 
    nacks = 0

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
    
    def rdt_2_1_send(self, msg_S, ack_nak = 00):
        self.last_packet = []
        p = PacketRDT21(self.seq_num, msg_S, ack_nak)
        self.seq_num += 1
        self.last_packet.append(p)
        #print(str(self.nacks))
        self.network.udt_send(p.get_byte_S())

    def rdt_2_1_resend(self):
        if (self.nacks > 0):
            self.last_packet.pop

        self.network.udt_send(self.last_packet[-1].get_byte_S())

    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S
            length = int(self.byte_buffer[Packet.type_length:Packet.type_length+Packet.length_S_length])
            if len(self.byte_buffer) < length:
                #sleep(0.5)
                return ret_S
            #create packet from buffer content and add to return strin
            p = PacketRDT21.from_byte_S(self.byte_buffer[0:length])
            #check the checksum and send nak if corrupt
            if(PacketRDT21.corrupt(self.byte_buffer)):
                println("got corrupt packet")
                self.nacks += 1
                self.rdt_2_1_send("", 11)
            elif(PacketRDT21.is_nak(p.ack_nak)):   #if nak
                print("got NAK")
                self.nacks -= 1
                self.rdt_2_1_resend()
            elif(PacketRDT21.is_ack(p.ack_nak)):                                  #send ack if not corrupt
                print("recieved ACK")
                self.nacks = 0
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]


    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

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
        


        
        