from .base import BaseFormatter


class BasicSrcDstActionFormatter(BaseFormatter):
    """
    Basic formatter which displays source and destination pairs as
    well as the resulting action.
    """
    def format(self):
        for line in self.entries:
            print("{date:20} {proto:10} SRC: {srcip:39}  DST: "
                  "{dstip:39} SPT: {spt:<8} DPT: {dpt:<8} ACTION: "
                  "{action}"
                  .format(date=line.date.strftime('%b %d %H:%M:%S'),
                          proto=line.get_proto(), srcip=line.src,
                          dstip=line.dst, spt=line.spt, dpt=line.dpt,
                          action=self.get_action_repr(line)))
