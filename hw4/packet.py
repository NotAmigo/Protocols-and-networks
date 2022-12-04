class Packet:
    def __init__(self, packet, dst: str, session_id: int, seq: int):
        self.packet = packet
        self.id = session_id
        self.seq = seq
        self.dst = dst

    def get_packet(self, ttl: int):
        raise NotImplementedError
