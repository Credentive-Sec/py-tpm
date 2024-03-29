import abc

class TpmDevice(abc.ABC):
    # Returns an error object if connection attempt fails before asyncronous phase commences
    @abc.abstractmethod
    def connect(self):
        pass

    # Sends the command buffe in the TPM wire format to the TPM device,
    # and returns the TPM response buffer via the callback.
    @abc.abstractmethod
    def dispatchCommand(self, commandBuffer) -> bytes:
        pass

    # Closes the connection with the TPM device and releases associated system resources
    @abc.abstractmethod
    def close(self):
        pass

class TpmTbsDevice(TpmDevice): # Windows TPM API
    # override
    def connect(self):
        from ctypes import cdll, Structure, byref, c_int, c_void_p
        self.__tbs = cdll.LoadLibrary('Tbs')
        self.__tbsCtx = c_void_p()
        self.__c_int = c_int
        self.__byref = byref

        class TbsContextParams(Structure):
            _fields_ = [("version", c_int),
                        ("params", c_int)]

        tbsCtxParams = TbsContextParams(2, 1 << 2)
        res = self.__tbs.Tbsi_Context_Create(byref(tbsCtxParams), byref(self.__tbsCtx))
        if (res != 0):
            raise(Exception('Tbsi_Context_Create() failed: error ' + hex(res)))

    # override
    def dispatchCommand(self, commandBuffer):
        responseBuffer = bytes(4096)
        respLen = self.__c_int(4096)
        res = self.__tbs.Tbsip_Submit_Command(self.__tbsCtx, 0, 0, bytes(commandBuffer), len(commandBuffer), responseBuffer, self.__byref(respLen))
        if (res != 0):
            raise(Exception('Tbsip_Submit_Command() failed: error ' + hex(res)))
        return responseBuffer[:respLen.value]

    # override
    def close(self):
        if (self.__tbs):
            res = self.__tbs.Tbsip_Context_Close(self.__tbsCtx)
            if (res != 0):
                raise(Exception('Tbsi_Context_Close() failed: error ' + hex(res)))

# end of class TpmTbsDevice
            
class TpmLinuxDevice(TpmDevice):

    # override
    def connect(self):
        try:
            self.__devTpmHandle = open('/dev/tpm0', 'wb+', buffering=0)
            #print('Connected to the raw TPM device')
        except:
            try:
                self.__devTpmHandle = open('/dev/tpmrm0', 'wb+', buffering=0)
                #print('Connected to the kernel TRM')
            except :
                raise(Exception('Failed to connect to the system TPM'))

    # override
    def dispatchCommand(self, commandBuffer):
        self.__devTpmHandle.write(commandBuffer)
        return self.__devTpmHandle.read()

    # override
    def close(self):
        if (self.__devTpmHandle):
            self.__devTpmHandle.close()

# end of class TpmLinuxDevice
            
