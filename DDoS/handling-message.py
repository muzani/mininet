from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.logger.info("start init")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info("paket handler %s", ofproto)

        # Proses paket masuk
        in_port = msg.match['in_port']
        self.logger.info("Packet received at switch %s from port %s",
                         dp.id, in_port)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions
        )
        dp.send_msg(out)


#test
#run
# ryu-manager simple_switch.py

#attack
# hping3 -S -p 80 --flood <IP_TARGET>

#h1 hping3 -c 100 [IP_of_h2]
#https://www.researchgate.net/figure/generating-UDP-normal-packets_fig7_340663367

