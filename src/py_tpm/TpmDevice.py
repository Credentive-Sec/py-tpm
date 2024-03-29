import abc
import socket
from .TpmTypes import *
from . import _internal










class TSS_TPM_INFO(TpmEnum):
    # Flags corresponding to the TpmEndPointInfo values used by the TPM simulator
    TSS_TpmPlatformAvailable = 0x01
    TSS_TpmUsesTbs = 0x02
    TSS_TpmInRawMode = 0x04
    TSS_TpmSupportsPP = 0x08

    # TPM connection type. Flags are mutually exclusive for better error checking
    TSS_SocketConn = 0x1000
    TSS_TbsConn = 0x2000


class TPM_TCP_PROTOCOL(TpmEnum):
    SignalPowerOn = 1
    #SignalPowerOff = 2
    SendCommand = 8
    SignalNvOn = 11
    #SignalNvOff = 12
    HandShake = 15
    SessionEnd = 20
    Stop = 21

def int32toTpm(val):
    return intToTpm(val, 4)
    #v = int(val)
    #return (v & 0xFF) << 24 | (v & 0xFF00) << 8 | (v & 0xFF0000) >> 8 | (v & 0xFF000000) >> 24
    #return bytesFromList([(v & 0xFF000000) >> 24, (v & 0xFF0000) >> 16, (v & 0xFF00) >> 8, v & 0xFF])

def int16toTpm(val):
    return intToTpm(val, 2)
    #v = int(val)
    #return (v & 0xFF) << 8 | (v & 0xFF00) >> 8
    #return bytesFromList([(v & 0xFF00) >> 8, v & 0xFF])

class TpmTcpDevice(TpmDevice):
    def __init__(self, host = '127.0.0.1', port = 2321, linuxTrm = False):
        self.__host = host
        self.__port = port
        self.__linuxTrm = linuxTrm
        self.__oldTrm = True
        self.__tpmSocket: socket.socket
        self.__platSocket: socket.socket
        self.__tpmInfo: int

    # override
    def connect(self):
        self.__tpmSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__platSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.__tpmSocket.connect((self.__host, self.__port))
        if (self.__linuxTrm):
            #raise(Exception('Linux TRM not impl'))
            cmdGetRandom = bytesFromList(
                               [0x80, 0x01,             # TPM_ST_NO_SESSIONS
                                0, 0, 0, 0x0C,          # length
                                0, 0, 0x01, 0x7B,       # TPM_CC_GetRandom
                                0, 0x08                 # Cmd param
            ])
            try:
                resp = self.dispatchCommand(cmdGetRandom)
            except:
                resp = []
            if (len(resp) != 20):
                if (self.__oldTrm):
                    self.__oldTrm = False
                    self.close()
                    self.connect()
                else:
                    raise(Exception('Connection to Linux TRM failed'))
                #raise(Exception('Probe TPM2_GetRandom() failed'))
            #else: connection to Linux TRM established
        else:
            ClientVer = 1
            req = bytesFromList([0, 0, 0, int(TPM_TCP_PROTOCOL.HandShake),
                                 0, 0, 0, int(ClientVer)])
            self.__tpmSocket.send(req)
            resp = bytesFromList([])
            while (len(resp) < 12):
                resp = resp + self.__tpmSocket.recv(32)
            if (len(resp) != 12):
                raise(Exception('Wrong length of the handshake response ' + str(len(resp)) + ' bytes instead of 12'))
            svrVer = intFromTpm(resp, 0, 4)
            if (svrVer != ClientVer):
                raise(Exception('Too old TCP server version:', svrVer))
            self.__tpmInfo = intFromTpm(resp, 4, 4)
            ack = intFromTpm(resp, 8, 4)
            if (ack != 0):
                raise(Exception('Bad ack', ack, 'for the handshake sequence'))
            self.__tpmInfo |= int(TSS_TPM_INFO.TSS_SocketConn);

            self.__platSocket.connect((self.__host, self.__port + 1))

            platReq = bytesFromList([0, 0, 0, int(TPM_TCP_PROTOCOL.SignalPowerOn)])
            self.__platSocket.send(platReq)
            platResp = self.__platSocket.recv(32)
            ack = intFromTpm(platResp, 0, 4)
            if (len(platResp) != 4 or ack != 0):
                raise(Exception('Bad ack ' + str(ack) + ' for the simulator Power-ON command'))

            platReq = bytesFromList([0, 0, 0, int(TPM_TCP_PROTOCOL.SignalNvOn)])
            self.__platSocket.send(platReq)
            platResp = self.__platSocket.recv(32)
            ack = intFromTpm(platResp, 0, 4)
            if (len(platResp) != 4 or ack != 0):
                raise(Exception('Bad ack ' + str(ack) + ' for the simulator NV-ON command'))

            cmdStartup = bytesFromList([
                    0x80, 0x01,             # TPM_ST_NO_SESSIONS
                    0, 0, 0, 0x0C,          # Cmd buf length
                    0, 0, 0x01, 0x44,       # TPM_CC_Startup
                    0, 0                    # Cmd param: TPM_SU_CLEAR
                ])
            self.dispatchCommand(cmdStartup)

    # override
    def dispatchCommand(self, commandBuffer):
        self.__tpmSocket.send(int32toTpm(TPM_TCP_PROTOCOL.SendCommand))
        # locality
        self.__tpmSocket.send(bytesFromList([0]))
        if (self.__linuxTrm and self.__oldTrm):
            # debugMsgLevel, commandSent status bit
            self.__tpmSocket.send(bytesFromList([0, 1]))
        self.__tpmSocket.send(int32toTpm(len(commandBuffer)))
        self.__tpmSocket.send(commandBuffer)
        
        resp = self.__tpmSocket.recv(4096)
        respLen = intFromTpm(resp, 0, 4)
        while (len(resp) < respLen + 8):
            resp = resp + self.__tpmSocket.recv(4096)
        #print('dispatchCommand returned', len(resp), 'bytes; reported in the header', respLen)
        if (respLen != len(resp) - 8):
            raise(Exception('Invalid size tag ' + str(respLen) + ' for the TPM response of '
                                      + str(len(resp) - 8) + ' bytes'))
        ack = intFromTpm(resp, respLen + 4, 4)
        if (ack != 0):
            raise(Exception('Bad ack during regular command dispatch'))
        return resp[4 : respLen + 4]

    # override
    def close(self):
        if (self.__tpmSocket):
            self.__tpmSocket.close()
        if (self.__platSocket):
            self.__platSocket.close()
# end of class TpmTcpDevice
