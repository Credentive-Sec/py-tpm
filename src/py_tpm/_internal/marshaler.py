import abc

class TpmMarshaller(abc.ABC):
    'Base interface for all marshalable non-trivial TPM data types'

    @abc.abstractmethod
    def toTpm(self, buf):
        """Convert this object to its TPM representation and store in the output byte buffer object
    
        Parameters
        ----------
        buf: TpmBuffer
            Output byte buffer for the marshaled representation of this object
        """
        pass

    @abc.abstractmethod
    def fromTpm(self, buf):
        """Populate this object from the TPM representation in the input byte buffer object

        Parameters
        ----------
        buf: TpmBuffer
            Input byte buffer with the marshaled representation of the object
        """
        pass
    # interface TpmMarshaller