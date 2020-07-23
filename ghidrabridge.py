# Forms a bridge between libvirtdma and Ghidra for memory acquisition
#@author Can Selcik
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from __main__ import *
import urllib2

class VirtProcDMA(object):
    def __init__(self, vdma, dirbase):
        self.vdma = vdma
        self.dirbase = dirbase

    def readhex(self, vaddr, length):
        return self.vdma.readhex(self.dirbase, vaddr, length)

    def read2frag(self, vaddr, length):
        return self.vdma.read2frag(self.dirbase, vaddr, length)


class VirtDMA(object):
    def __init__(self, hostport):
        self.hostport = hostport

    def with_dirbase(self, dirbase):
        return VirtProcDMA(self, dirbase)

    def readhex(self, dirbase, vaddr, length):
        url = "http://{}/dma/pmemread/{}/{}/{}".format(self.hostport, dirbase, vaddr, length)
        return urllib2.urlopen(url).read()

    def read2frag(self, dirbase, vaddr, length):  
        hexcontents = self.readhex(dirbase, vaddr, length)
        contents = bytearray.fromhex(hexcontents)
        segname = ".vdma{}".format(hex(vaddr))
        mem = currentProgram.getMemory()
        writeAddr = toAddr(vaddr)
        frag = mem.getBlock(writeAddr)
        if frag is None:
            try:
                new_frag = mem.createUninitializedBlock(segname, writeAddr, length, False)
                frag = new_frag
            except Exception as e:
                print "Failed to create new fragment:", e
                return False
        if writeAddr > frag.end or writeAddr < frag.start:
            print "Fragment start/end doesn't match the payload we want to import"
            return False
        if not frag.isInitialized():
            frag = mem.convertToInitialized(frag, 0)
        frag.putBytes(writeAddr, str(contents))
        return True

def default():
    return VirtDMA("localhost:2222")

def default_with_dirbase(dirbase):
    return default().with_dirbase(dirbase)

# Helper/Caller below:
#
# from __main__ import *
# import libvirtdma
#
# def get_dirbase():
#     propman = currentProgram.getUsrPropertyManager()
#     mp = propman.getStringPropertyMap("CurrentProgramDirbase")
#     if mp is None:
#         return None
#     return mp.getFirstPropertyAddress()
#
# def store_dirbase(dirbase):
#     propman = currentProgram.getUsrPropertyManager()
#     mp = propman.getStringPropertyMap("CurrentProgramDirbase")
#     if mp is not None:
#         propman.removePropertyMap("CurrentProgramDirbase")
#     mp = propman.createStringPropertyMap("CurrentProgramDirbase")
#     mp.add(dirbase, "value")
#
# def get_or_ask_dirbase():
#     dirbase = get_dirbase()
#     if dirbase is None:
#         dirbase = askAddress("DirectoryTableBase for Process", "DirTableBase")
#         store_dirbase(dirbase)
#     return dirbase
#
# dma = libvirtdma.default_with_dirbase(get_or_ask_dirbase().offset)
#
# beginaddr = None
# endaddr = None
# if currentSelection is not None:
#     selection = currentSelection.getFirstRange()
#     if selection is not None:
#         beginaddr = selection.getMinAddress()
#         endaddr = selection.getMaxAddress()
#
# if beginaddr is None or endaddr is None:
#     loc = currentLocation
#     if loc is not None:
#         beginaddr = loc.getAddress()
#         size = askInt("Length of the read", "Length in bytes")
#         endaddr = beginaddr.add(size)
# if beginaddr is None:
#     beginaddr = askAddress("Beginning of the read", "Begin Address")
# if endaddr is None:
#     endaddr = askAddress("End of the read", "End Address")
#
# size = endaddr.offset - beginaddr.offset
# print "Fetching from %x to %x (len: %d bytes)..." % (beginaddr.offset, endaddr.offset, size)
# dma.read2frag(beginaddr.offset, size)
# print "DONE"
