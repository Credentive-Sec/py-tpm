class TpmError(Exception):
    def __init__(self, responseCode, tpmCommand, errorMessage):
        Exception.__init__(self, errorMessage)
        self.responseCode = responseCode
        self.tpmCommand = tpmCommand
        #self.errorMessage = errorMessage