from packet import Packet
from ping import Ping
from answer_formatter import AnswerFormatter, Answer
from ipwhois.net import Net
from ipwhois.asn import IPASN


class Traceroute:
    def __init__(self, dst: str, packet: Packet, max_ttl: int, repeat: int,
                 timeout: int, interval: int, debug: bool, verbose: bool):
        self.dst = dst
        self.packet = packet
        self.interval = interval
        self.max_ttl = max_ttl
        self.repeat = repeat
        self.timeout = timeout
        self.is_in_debug_mode = debug
        self.verbose = verbose

    @staticmethod
    def who_is(address):
        try:
            test = IPASN(Net(address)).lookup()['asn']
        except:
            test = ''
        return test

    def run(self):
        previous_address = None
        for ttl in range(1, self.max_ttl + 1):
            ttl_packet = self.packet.get_packet(ttl)
            ping = Ping(ttl_packet, self.timeout, self.repeat, self.interval)
            answer = ping.make_ping()
            asn = self.who_is(answer[0])
            if previous_address is not None and answer[0] == previous_address:
                break

            if self.is_in_debug_mode:
                self.__show_debug_info(ttl, answer)

            print(f"{str(ttl).ljust(6)} {AnswerFormatter(answer)} {asn if self.verbose else ''}")
            previous_address = answer[0]

    @staticmethod
    def __show_debug_info(ttl: int, answer: Answer):
        print(f"ttl: {ttl}")
        print(f"address: {answer[0]}")
        print(f"timestamps: {answer[1]}")
        print()

