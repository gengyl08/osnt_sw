import os
from scapy import *
from scapy.all import *

class CBR_Engine:
    # pkt_rate in pkts/second, pkt_length in bytes
    def __init__(self, engine_name, pkt_rate, pkt_length):
        self.engine_name = engine_name
        self.pkt_rate = float(pkt_rate)
        self.pkt_length = pkt_length

    def generate(self, pkt_number):
        pkts = [None]*pkt_number
        for i in range(pkt_number):
            pkts[i] = Ether(''.join('X' for i in range(self.pkt_length)))
            pkts[i].time = i/self.pkt_rate
        wrpcap(self.engine_name + '.cap', pkts)

class Poisson_Engine:
    def __init__(self, engine_name, pkt_rate, pkt_length):
        self.engine_name = engine_name
        self.pkt_rate = float(pkt_rate)
        self.pkt_length = pkt_length

    def generate(self, pkt_number):
        pkts = [None]*pkt_number
        time = 0
        for i in range(pkt_number):
            pkts[i] = Ether(''.join('X' for i in range(self.pkt_length)))
            delta = random.expovariate(self.pkt_rate)
            pkts[i].time = time + delta
            time = time + delta
        wrpcap(self.engine_name + '.cap', pkts)

class Port_Arbiter:
    def __init__(self, iface, engine_list):
        self.iface = iface
        self.engine_list = engine_list

    def merge_queues():
        pos = [0]*len(engine_list);
        pcap_list = [None]*len(engine_list);
        for i in range(len(engine_list)):
            pcap_list[i] = rdpcap(engine_list[i] + '.cap')
        queues_num = range(len(engine_list))
        pkts_num = sum(len(pkts) for pkts in pcap_list)
        pkts = [None]*pkts_num
        while(sum(pos)<pkts_num):
            queue_id = 0
            for i in range(queues_num):
                if(pos[i] < len(pcap_list[i]) and pcap_list[i][pos[i]].time < pcap_list[queue_id][pos[queue_id]]):
                    queue_id = i
            pkts[sum(pos)] = pcap_list[queue_id][pos[queue_id]]
            pos[queue_id] = pos[queue_id] + 1
        wrpcap(iface + '.cap', pkts)


if __name__=="__main__":

    cbr = CBR_Engine('cbr', 100, 20)
    cbr.generate(10)

    poisson = Poisson_Engine('poisson', 100, 20)
    poisson.generate(10)

    arbiter = Port_Arbiter('eth1', ['cbr', 'poisson'])
    arbiter.merge_queues()
