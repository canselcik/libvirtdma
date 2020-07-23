import urllib2
import idautils
import idc
import idaapi

def segment_exists(segment_name):
    for s in idautils.Segments():
        if idc.SegName(s) == segment_name:
            return True
    return False

class VirtDMA(object):
    def __init__(self, hostport):
        self.hostport = hostport

    def readhex(self, dirbase, vaddr, length):
        url = "http://{}/dma/pmemread/{}/{}/{}".format(self.hostport, dirbase, vaddr, length)
        return urllib2.urlopen(url).read()

    def read2seg(self, dirbase, vaddr, length):
        hexcontents = self.readhex(dirbase, vaddr, length)
        contents = bytearray.fromhex(hexcontents)
        segname = ".vdma{}".format(hex(vaddr))
        if segment_exists(segname):
            found = False
            for i in range(100):
                potential_name = "{}_{}".format(segname, i)
                if not segment_exists(potential_name):
                    segname = potential_name
                    found = True
                    break
            if not found:
                print "Unable to find a name for the segment that's not taken"
                return False
        if len(contents) != length:
            print "Decoded length doesn't match expected length, aborting."
            return False
        segment_end = vaddr + length
        if idc.SegCreate(vaddr, segment_end, 0, 1, 0, 0) == 0:
            print "Failed to create segment"
            return False
        if idc.SegRename(vaddr, segname) == 0:
            print "Failed to rename the created segment at %p" % vaddr
            return False
        return idaapi.mem2base(str(contents), vaddr, segment_end) == 1
