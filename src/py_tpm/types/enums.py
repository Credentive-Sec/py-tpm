from enum import IntFlag, Flag

class TPM_ALG_ID(IntFlag): # UINT16
    """ Table 2 is the list of algorithms to which the TCG has assigned an
    algorithm identifier along with its numeric identifier.
    """

    ERROR = 0x0000
    """ Should not occur """

    FIRST = 0x0001
    """ An object type that contains an RSA key """

    RSA = 0x0001
    """ An object type that contains an RSA key """

    TDES = 0x0003
    """ Block cipher with various key sizes (Triple Data Encryption
    Algorithm, commonly called Triple Data Encryption Standard)
    """

    SHA = 0x0004
    """ Hash algorithm producing a 160-bit digest """

    SHA1 = 0x0004
    """ Redefinition for documentation consistency """

    HMAC = 0x0005
    """ Hash Message Authentication Code (HMAC) algorithm """

    AES = 0x0006
    """ Block cipher with various key sizes """

    MGF1 = 0x0007
    """ Hash-based mask-generation function """

    KEYEDHASH = 0x0008
    """ An object type that may use XOR for encryption or an HMAC for
    signing and may also refer to a data object that is neither signing nor
    encrypting
    """

    XOR = 0x000A
    """ Hash-based stream cipher """

    SHA256 = 0x000B
    """ Hash algorithm producing a 256-bit digest """

    SHA384 = 0x000C
    """ Hash algorithm producing a 384-bit digest """

    SHA512 = 0x000D
    """ Hash algorithm producing a 512-bit digest """

    NULL = 0x0010
    """ Indication that no algorithm is selected """

    SM3_256 = 0x0012
    """ Hash algorithm producing a 256-bit digest """

    SM4 = 0x0013
    """ Symmetric block cipher with 128 bit key """

    RSASSA = 0x0014
    """ A signature algorithm defined in section 8.2 (RSASSA-PKCS1-v1_5) """

    RSAES = 0x0015
    """ A padding algorithm defined in section 7.2 (RSAES-PKCS1-v1_5) """

    RSAPSS = 0x0016
    """ A signature algorithm defined in section 8.1 (RSASSA-PSS) """

    OAEP = 0x0017
    """ A padding algorithm defined in Section 7.1 (RSAES_OAEP) """

    ECDSA = 0x0018
    """ Signature algorithm using elliptic curve cryptography (ECC) """

    ECDH = 0x0019
    """ Secret sharing using ECC Based on context, this can be either
    One-Pass Diffie-Hellman, C(1, 1, ECC CDH) defined in 6.2.2.2 or Full
    Unified Model C(2, 2, ECC CDH) defined in 6.1.1.2
    """

    ECDAA = 0x001A
    """ Elliptic-curve based, anonymous signing scheme """

    SM2 = 0x001B
    """ Depending on context, either an elliptic-curve-based signature
    algorithm, encryption algorithm, or key exchange protocol
    """

    ECSCHNORR = 0x001C
    """ Elliptic-curve based Schnorr signature """

    ECMQV = 0x001D
    """ Two-phase elliptic-curve key exchange C(2, 2, ECC MQV) Section 6.1.1.4 """

    KDF1_SP800_56A = 0x0020
    """ Concatenation key derivation function (approved alternative 1)
    Section 5.8.1
    """

    KDF2 = 0x0021
    """ Key derivation function KDF2 Section 13.2 """

    KDF1_SP800_108 = 0x0022
    """ A key derivation method SP800-108, Section 5.1 KDF in Counter Mode """

    ECC = 0x0023
    """ Prime field ECC """

    SYMCIPHER = 0x0025
    """ The object type for a symmetric block cipher key """

    CAMELLIA = 0x0026
    """ Symmetric block cipher with various key sizes """

    SHA3_256 = 0x0027
    """ Hash algorithm producing a 256-bit digest """

    SHA3_384 = 0x0028
    """ Hash algorithm producing a 384-bit digest """

    SHA3_512 = 0x0029
    """ Hash algorithm producing a 512-bit digest """

    CMAC = 0x003F

    CTR = 0x0040
    """ Counter mode if implemented, all symmetric block ciphers (S type)
    implemented shall be capable of using this mode.
    """

    OFB = 0x0041
    """ Output Feedback mode if implemented, all symmetric block ciphers (S
    type) implemented shall be capable of using this mode.
    """

    CBC = 0x0042
    """ Cipher Block Chaining mode if implemented, all symmetric block
    ciphers (S type) implemented shall be capable of using this mode.
    """

    CFB = 0x0043
    """ Cipher Feedback mode if implemented, all symmetric block ciphers (S
    type) implemented shall be capable of using this mode.
    """

    ECB = 0x0044
    """ Electronic Codebook mode if implemented, all implemented symmetric
    block ciphers (S type) shall be capable of using this mode.
    NOTE This mode is not recommended for uses unless the key is frequently
    rotated such as in video codecs
    """

    LAST = 0x0044

    ANY = 0x7FFF
    """ Phony alg ID to be used for the first union member with no selector """

    ANY2 = 0x7FFE
    """ Phony alg ID to be used for the second union member with no selector """
# enum TPM_ALG_ID

class TPM_ECC_CURVE(IntFlag): # UINT16
    """ Table 4 is the list of identifiers for TCG-registered curve ID
    values for elliptic curve cryptography.
    """

    NONE = 0x0000

    NIST_P192 = 0x0001

    NIST_P224 = 0x0002

    NIST_P256 = 0x0003

    NIST_P384 = 0x0004

    NIST_P521 = 0x0005

    BN_P256 = 0x0010
    """ Curve to support ECDAA """

    BN_P638 = 0x0011
    """ Curve to support ECDAA """

    SM2_P256 = 0x0020

    TEST_P192 = 0x0021
# enum TPM_ECC_CURVE

class SHA1(IntFlag): # UINT32
    """ Table 13 Defines for SHA1 Hash Values """

    DIGEST_SIZE = 20
    """ Size of digest in octets """

    BLOCK_SIZE = 64
    """ Size of hash block in octets """
# enum SHA1

class SHA256(IntFlag): # UINT32
    """ Table 14 Defines for SHA256 Hash Values """

    DIGEST_SIZE = 32
    """ Size of digest """

    BLOCK_SIZE = 64
    """ Size of hash block """
# enum SHA256

class SHA384(IntFlag): # UINT32
    """ Table 15 Defines for SHA384 Hash Values """

    DIGEST_SIZE = 48
    """ Size of digest in octets """

    BLOCK_SIZE = 128
    """ Size of hash block in octets """
# enum SHA384

class SHA512(IntFlag): # UINT32
    """ Table 16 Defines for SHA512 Hash Values """

    DIGEST_SIZE = 64
    """ Size of digest in octets """

    BLOCK_SIZE = 128
    """ Size of hash block in octets """
# enum SHA512

class SM3_256(IntFlag): # UINT32
    """ Table 17 Defines for SM3_256 Hash Values """

    DIGEST_SIZE = 32
    """ Size of digest in octets """

    BLOCK_SIZE = 64
    """ Size of hash block in octets """
# enum SM3_256

class SHA3_256(IntFlag): # UINT32
    """ Table 18 Defines for SHA3_256 Hash Values """

    DIGEST_SIZE = 32
    """ Size of digest in octets """

    BLOCK_SIZE = 136
    """ Size of hash block in octets """
# enum SHA3_256

class SHA3_384(IntFlag): # UINT32
    """ Table 19 Defines for SHA3_384 Hash Values """

    DIGEST_SIZE = 48
    """ Size of digest in octets """

    BLOCK_SIZE = 104
    """ Size of hash block in octets """
# enum SHA3_384

class SHA3_512(IntFlag): # UINT32
    """ Table 20 Defines for SHA3_512 Hash Values """

    DIGEST_SIZE = 64
    """ Size of digest in octets """

    BLOCK_SIZE = 72
    """ Size of hash block in octets """
# enum SHA3_512

class Logic(IntFlag): # BYTE
    """ Table 4 Defines for Logic Values """

    TRUE = 1

    FALSE = 0

    YES = 1

    NO = 0

    SET = 1

    CLEAR = 0
# enum Logic

class TPM_SPEC(IntFlag): # UINT32
    """ These values are readable with TPM2_GetCapability() (see 6.13 for
    the format).
    """

    FAMILY = 0x322E3000
    """ ASCII 2.0 with null terminator """

    LEVEL = 0
    """ The level number for the specification """

    VERSION = 162
    """ The version number of the spec (001.62 * 100) """

    YEAR = 2019
    """ The year of the version """

    DAY_OF_YEAR = 360
    """ The day of the year (December 26) """
# enum TPM_SPEC

class TPM_GENERATED(IntFlag): # UINT32
    """ This constant value differentiates TPM-generated structures from
    non-TPM structures.
    """

    VALUE = 0xff544347
    """ 0xFF TCG (FF 54 43 4716) """
# enum TPM_GENERATED

class TPM_CC(IntFlag): # UINT32
    FIRST = 0x0000011F
    """ Compile variable. May decrease based on implementation. """

    NV_UndefineSpaceSpecial = 0x0000011F

    EvictControl = 0x00000120

    HierarchyControl = 0x00000121

    NV_UndefineSpace = 0x00000122

    ChangeEPS = 0x00000124

    ChangePPS = 0x00000125

    Clear = 0x00000126

    ClearControl = 0x00000127

    ClockSet = 0x00000128

    HierarchyChangeAuth = 0x00000129

    NV_DefineSpace = 0x0000012A

    PCR_Allocate = 0x0000012B

    PCR_SetAuthPolicy = 0x0000012C

    PP_Commands = 0x0000012D

    SetPrimaryPolicy = 0x0000012E

    FieldUpgradeStart = 0x0000012F

    ClockRateAdjust = 0x00000130

    CreatePrimary = 0x00000131

    NV_GlobalWriteLock = 0x00000132

    GetCommandAuditDigest = 0x00000133

    NV_Increment = 0x00000134

    NV_SetBits = 0x00000135

    NV_Extend = 0x00000136

    NV_Write = 0x00000137

    NV_WriteLock = 0x00000138

    DictionaryAttackLockReset = 0x00000139

    DictionaryAttackParameters = 0x0000013A

    NV_ChangeAuth = 0x0000013B

    PCR_Event = 0x0000013C
    """ PCR """

    PCR_Reset = 0x0000013D
    """ PCR """

    SequenceComplete = 0x0000013E

    SetAlgorithmSet = 0x0000013F

    SetCommandCodeAuditStatus = 0x00000140

    FieldUpgradeData = 0x00000141

    IncrementalSelfTest = 0x00000142

    SelfTest = 0x00000143

    Startup = 0x00000144

    Shutdown = 0x00000145

    StirRandom = 0x00000146

    ActivateCredential = 0x00000147

    Certify = 0x00000148

    PolicyNV = 0x00000149
    """ Policy """

    CertifyCreation = 0x0000014A

    Duplicate = 0x0000014B

    GetTime = 0x0000014C

    GetSessionAuditDigest = 0x0000014D

    NV_Read = 0x0000014E

    NV_ReadLock = 0x0000014F

    ObjectChangeAuth = 0x00000150

    PolicySecret = 0x00000151
    """ Policy """

    Rewrap = 0x00000152

    Create = 0x00000153

    ECDH_ZGen = 0x00000154

    HMAC = 0x00000155
    """ See NOTE 1 """

    MAC = 0x00000155
    """ See NOTE 1 """

    Import = 0x00000156

    Load = 0x00000157

    Quote = 0x00000158

    RSA_Decrypt = 0x00000159

    HMAC_Start = 0x0000015B
    """ See NOTE 1 """

    MAC_Start = 0x0000015B
    """ See NOTE 1 """

    SequenceUpdate = 0x0000015C

    Sign = 0x0000015D

    Unseal = 0x0000015E

    PolicySigned = 0x00000160
    """ Policy """

    ContextLoad = 0x00000161
    """ Context """

    ContextSave = 0x00000162
    """ Context """

    ECDH_KeyGen = 0x00000163

    EncryptDecrypt = 0x00000164

    FlushContext = 0x00000165
    """ Context """

    LoadExternal = 0x00000167

    MakeCredential = 0x00000168

    NV_ReadPublic = 0x00000169
    """ NV """

    PolicyAuthorize = 0x0000016A
    """ Policy """

    PolicyAuthValue = 0x0000016B
    """ Policy """

    PolicyCommandCode = 0x0000016C
    """ Policy """

    PolicyCounterTimer = 0x0000016D
    """ Policy """

    PolicyCpHash = 0x0000016E
    """ Policy """

    PolicyLocality = 0x0000016F
    """ Policy """

    PolicyNameHash = 0x00000170
    """ Policy """

    PolicyOR = 0x00000171
    """ Policy """

    PolicyTicket = 0x00000172
    """ Policy """

    ReadPublic = 0x00000173

    RSA_Encrypt = 0x00000174

    StartAuthSession = 0x00000176

    VerifySignature = 0x00000177

    ECC_Parameters = 0x00000178

    FirmwareRead = 0x00000179

    GetCapability = 0x0000017A

    GetRandom = 0x0000017B

    GetTestResult = 0x0000017C

    Hash = 0x0000017D

    PCR_Read = 0x0000017E
    """ PCR """

    PolicyPCR = 0x0000017F
    """ Policy """

    PolicyRestart = 0x00000180

    ReadClock = 0x00000181

    PCR_Extend = 0x00000182

    PCR_SetAuthValue = 0x00000183

    NV_Certify = 0x00000184

    EventSequenceComplete = 0x00000185

    HashSequenceStart = 0x00000186

    PolicyPhysicalPresence = 0x00000187
    """ Policy """

    PolicyDuplicationSelect = 0x00000188
    """ Policy """

    PolicyGetDigest = 0x00000189
    """ Policy """

    TestParms = 0x0000018A

    Commit = 0x0000018B

    PolicyPassword = 0x0000018C
    """ Policy """

    ZGen_2Phase = 0x0000018D

    EC_Ephemeral = 0x0000018E

    PolicyNvWritten = 0x0000018F
    """ Policy """

    PolicyTemplate = 0x00000190
    """ Policy """

    CreateLoaded = 0x00000191

    PolicyAuthorizeNV = 0x00000192
    """ Policy """

    EncryptDecrypt2 = 0x00000193

    AC_GetCapability = 0x00000194

    AC_Send = 0x00000195

    Policy_AC_SendSelect = 0x00000196
    """ Policy """

    CertifyX509 = 0x00000197

    ACT_SetTimeout = 0x00000198

    ECC_Encrypt = 0x00000199

    ECC_Decrypt = 0x0000019A

    LAST = 0x0000019A
    """ Compile variable. May increase based on implementation. """

    CC_VEND = 0x20000000

    Vendor_TCG_Test = CC_VEND+0x0000
    """ Used for testing of command dispatch """
# enum TPM_CC

class ImplementationConstants(IntFlag): # UINT32
    """ Architecturally defined constants """

    Ossl = 1

    Ltc = 2

    Msbn = 3

    Symcrypt = 4

    HASH_COUNT = 3

    MAX_SYM_KEY_BITS = 256

    MAX_SYM_KEY_BYTES = ((MAX_SYM_KEY_BITS + 7) // 8)

    MAX_SYM_BLOCK_SIZE = 16

    MAX_CAP_CC = TPM_CC.LAST

    MAX_RSA_KEY_BYTES = 256

    MAX_AES_KEY_BYTES = 32

    MAX_ECC_KEY_BYTES = 48

    LABEL_MAX_BUFFER = 32

    _TPM_CAP_SIZE = 0x4  # sizeof(UINT32)

    MAX_CAP_DATA = (1024-_TPM_CAP_SIZE-0x4)  # (MAX_CAP_BUFFER-_TPM_CAP_SIZE-sizeof(UINT32))

    MAX_CAP_ALGS = (MAX_CAP_DATA // 0x6)  # (MAX_CAP_DATA / sizeof(TPMS_ALG_PROPERTY))

    MAX_CAP_HANDLES = (MAX_CAP_DATA // 0x4)  # (MAX_CAP_DATA / sizeof(TPM_HANDLE))

    MAX_TPM_PROPERTIES = (MAX_CAP_DATA // 0x8)  # (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PROPERTY))

    MAX_PCR_PROPERTIES = (MAX_CAP_DATA // 0x5)  # (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PCR_SELECT))

    MAX_ECC_CURVES = (MAX_CAP_DATA // 0x2)  # (MAX_CAP_DATA / sizeof(TPM_ECC_CURVE))

    MAX_TAGGED_POLICIES = (MAX_CAP_DATA // 0x46)  # (MAX_CAP_DATA / sizeof(TPMS_TAGGED_POLICY))

    MAX_AC_CAPABILITIES = (MAX_CAP_DATA // 0x8)  # (MAX_CAP_DATA / sizeof(TPMS_AC_OUTPUT))

    MAX_ACT_DATA = MAX_CAP_DATA // 0xC  # MAX_CAP_DATA / sizeof(TPMS_ACT_DATA)
# enum ImplementationConstants

class TPM_RC(IntFlag): # UINT32
    """ In general, response codes defined in TPM 2.0 Part 2 will be
    unmarshaling errors and will have the F (format) bit SET. Codes that are
    unique to TPM 2.0 Part 3 will have the F bit CLEAR but the V (version)
    attribute will be SET to indicate that it is a TPM 2.0 response code.
    See Response Code Details in TPM 2.0 Part 1.
    """

    SUCCESS = 0x000

    BAD_TAG = 0x01E
    """ Defined for compatibility with TPM 1.2 """

    RC_VER1 = 0x100
    """ Set for all format 0 response codes """

    INITIALIZE = RC_VER1 + 0x000
    """ TPM not initialized by TPM2_Startup or already initialized """

    FAILURE = RC_VER1 + 0x001
    """ Commands not being accepted because of a TPM failure
    NOTE This may be returned by TPM2_GetTestResult() as the testResult parameter.
    """

    SEQUENCE = RC_VER1 + 0x003
    """ Improper use of a sequence handle """

    PRIVATE = RC_VER1 + 0x00B
    """ Not currently used """

    HMAC = RC_VER1 + 0x019
    """ Not currently used """

    DISABLED = RC_VER1 + 0x020
    """ The command is disabled """

    EXCLUSIVE = RC_VER1 + 0x021
    """ Command failed because audit sequence required exclusivity """

    AUTH_TYPE = RC_VER1 + 0x024
    """ Authorization handle is not correct for command """

    AUTH_MISSING = RC_VER1 + 0x025
    """ Command requires an authorization session for handle and it is not present. """

    POLICY = RC_VER1 + 0x026
    """ Policy failure in math operation or an invalid authPolicy value """

    PCR = RC_VER1 + 0x027
    """ PCR check fail """

    PCR_CHANGED = RC_VER1 + 0x028
    """ PCR have changed since checked. """

    UPGRADE = RC_VER1 + 0x02D
    """ For all commands other than TPM2_FieldUpgradeData(), this code
    indicates that the TPM is in field upgrade mode; for
    TPM2_FieldUpgradeData(), this code indicates that the TPM is not in
    field upgrade mode
    """

    TOO_MANY_CONTEXTS = RC_VER1 + 0x02E
    """ Context ID counter is at maximum. """

    AUTH_UNAVAILABLE = RC_VER1 + 0x02F
    """ AuthValue or authPolicy is not available for selected entity. """

    REBOOT = RC_VER1 + 0x030
    """ A _TPM_Init and Startup(CLEAR) is required before the TPM can resume
    operation.
    """

    UNBALANCED = RC_VER1 + 0x031
    """ The protection algorithms (hash and symmetric) are not reasonably
    balanced. The digest size of the hash must be larger than the key size
    of the symmetric algorithm.
    """

    COMMAND_SIZE = RC_VER1 + 0x042
    """ Command commandSize value is inconsistent with contents of the
    command buffer; either the size is not the same as the octets loaded by
    the hardware interface layer or the value is not large enough to hold a
    command header
    """

    COMMAND_CODE = RC_VER1 + 0x043
    """ Command code not supported """

    AUTHSIZE = RC_VER1 + 0x044
    """ The value of authorizationSize is out of range or the number of
    octets in the Authorization Area is greater than required
    """

    AUTH_CONTEXT = RC_VER1 + 0x045
    """ Use of an authorization session with a context command or another
    command that cannot have an authorization session.
    """

    NV_RANGE = RC_VER1 + 0x046
    """ NV offset+size is out of range. """

    NV_SIZE = RC_VER1 + 0x047
    """ Requested allocation size is larger than allowed. """

    NV_LOCKED = RC_VER1 + 0x048
    """ NV access locked. """

    NV_AUTHORIZATION = RC_VER1 + 0x049
    """ NV access authorization fails in command actions (this failure does
    not affect lockout.action)
    """

    NV_UNINITIALIZED = RC_VER1 + 0x04A
    """ An NV Index is used before being initialized or the state saved by
    TPM2_Shutdown(STATE) could not be restored
    """

    NV_SPACE = RC_VER1 + 0x04B
    """ Insufficient space for NV allocation """

    NV_DEFINED = RC_VER1 + 0x04C
    """ NV Index or persistent object already defined """

    BAD_CONTEXT = RC_VER1 + 0x050
    """ Context in TPM2_ContextLoad() is not valid """

    CPHASH = RC_VER1 + 0x051
    """ CpHash value already set or not correct for use """

    PARENT = RC_VER1 + 0x052
    """ Handle for parent is not a valid parent """

    NEEDS_TEST = RC_VER1 + 0x053
    """ Some function needs testing. """

    NO_RESULT = RC_VER1 + 0x054
    """ Returned when an internal function cannot process a request due to
    an unspecified problem. This code is usually related to invalid
    parameters that are not properly filtered by the input unmarshaling code.
    """

    SENSITIVE = RC_VER1 + 0x055
    """ The sensitive area did not unmarshal correctly after decryption this
    code is used in lieu of the other unmarshaling errors so that an
    attacker cannot determine where the unmarshaling error occurred
    """

    RC_MAX_FM0 = RC_VER1 + 0x07F
    """ Largest version 1 code that is not a warning """

    RC_FMT1 = 0x080
    """ This bit is SET in all format 1 response codes
    The codes in this group may have a value added to them to indicate the
    handle, session, or parameter to which they apply.
    """

    ASYMMETRIC = RC_FMT1 + 0x001
    """ Asymmetric algorithm not supported or not correct """

    ATTRIBUTES = RC_FMT1 + 0x002
    """ Inconsistent attributes """

    HASH = RC_FMT1 + 0x003
    """ Hash algorithm not supported or not appropriate """

    VALUE = RC_FMT1 + 0x004
    """ Value is out of range or is not correct for the context """

    HIERARCHY = RC_FMT1 + 0x005
    """ Hierarchy is not enabled or is not correct for the use """

    KEY_SIZE = RC_FMT1 + 0x007
    """ Key size is not supported """

    MGF = RC_FMT1 + 0x008
    """ Mask generation function not supported """

    MODE = RC_FMT1 + 0x009
    """ Mode of operation not supported """

    TYPE = RC_FMT1 + 0x00A
    """ The type of the value is not appropriate for the use """

    HANDLE = RC_FMT1 + 0x00B
    """ The handle is not correct for the use """

    KDF = RC_FMT1 + 0x00C
    """ Unsupported key derivation function or function not appropriate for use """

    RANGE = RC_FMT1 + 0x00D
    """ Value was out of allowed range. """

    AUTH_FAIL = RC_FMT1 + 0x00E
    """ The authorization HMAC check failed and DA counter incremented """

    NONCE = RC_FMT1 + 0x00F
    """ Invalid nonce size or nonce value mismatch """

    PP = RC_FMT1 + 0x010
    """ Authorization requires assertion of PP """

    SCHEME = RC_FMT1 + 0x012
    """ Unsupported or incompatible scheme """

    SIZE = RC_FMT1 + 0x015
    """ Structure is the wrong size """

    SYMMETRIC = RC_FMT1 + 0x016
    """ Unsupported symmetric algorithm or key size, or not appropriate for
    instance
    """

    TAG = RC_FMT1 + 0x017
    """ Incorrect structure tag """

    SELECTOR = RC_FMT1 + 0x018
    """ Union selector is incorrect """

    INSUFFICIENT = RC_FMT1 + 0x01A
    """ The TPM was unable to unmarshal a value because there were not
    enough octets in the input buffer
    """

    SIGNATURE = RC_FMT1 + 0x01B
    """ The signature is not valid """

    KEY = RC_FMT1 + 0x01C
    """ Key fields are not compatible with the selected use """

    POLICY_FAIL = RC_FMT1 + 0x01D
    """ A policy check failed """

    INTEGRITY = RC_FMT1 + 0x01F
    """ Integrity check failed """

    TICKET = RC_FMT1 + 0x020
    """ Invalid ticket """

    RESERVED_BITS = RC_FMT1 + 0x021
    """ Reserved bits not set to zero as required """

    BAD_AUTH = RC_FMT1 + 0x022
    """ Authorization failure without DA implications """

    EXPIRED = RC_FMT1 + 0x023
    """ The policy has expired """

    POLICY_CC = RC_FMT1 + 0x024
    """ The commandCode in the policy is not the commandCode of the command
    or the command code in a policy command references a command that is not
    implemented
    """

    BINDING = RC_FMT1 + 0x025
    """ Public and sensitive portions of an object are not cryptographically
    bound
    """

    CURVE = RC_FMT1 + 0x026
    """ Curve not supported """

    ECC_POINT = RC_FMT1 + 0x027
    """ Point is not on the required curve. """

    RC_WARN = 0x900
    """ Set for warning response codes """

    CONTEXT_GAP = RC_WARN + 0x001
    """ Gap for context ID is too large """

    OBJECT_MEMORY = RC_WARN + 0x002
    """ Out of memory for object contexts """

    SESSION_MEMORY = RC_WARN + 0x003
    """ Out of memory for session contexts """

    MEMORY = RC_WARN + 0x004
    """ Out of shared object/session memory or need space for internal operations """

    SESSION_HANDLES = RC_WARN + 0x005
    """ Out of session handles a session must be flushed before a new
    session may be created
    """

    OBJECT_HANDLES = RC_WARN + 0x006
    """ Out of object handles the handle space for objects is depleted and a
    reboot is required
    NOTE 1 This cannot occur on the reference implementation.
    NOTE 2 There is no reason why an implementation would implement a design
    that would deplete handle space. Platform specifications are encouraged
    to forbid it.
    """

    LOCALITY = RC_WARN + 0x007
    """ Bad locality """

    YIELDED = RC_WARN + 0x008
    """ The TPM has suspended operation on the command; forward progress was
    made and the command may be retried
    See TPM 2.0 Part 1, Multi-tasking.
    NOTE This cannot occur on the reference implementation.
    """

    CANCELED = RC_WARN + 0x009
    """ The command was canceled """

    TESTING = RC_WARN + 0x00A
    """ TPM is performing self-tests """

    REFERENCE_H0 = RC_WARN + 0x010
    """ The 1st handle in the handle area references a transient object or
    session that is not loaded
    """

    REFERENCE_H1 = RC_WARN + 0x011
    """ The 2nd handle in the handle area references a transient object or
    session that is not loaded
    """

    REFERENCE_H2 = RC_WARN + 0x012
    """ The 3rd handle in the handle area references a transient object or
    session that is not loaded
    """

    REFERENCE_H3 = RC_WARN + 0x013
    """ The 4th handle in the handle area references a transient object or
    session that is not loaded
    """

    REFERENCE_H4 = RC_WARN + 0x014
    """ The 5th handle in the handle area references a transient object or
    session that is not loaded
    """

    REFERENCE_H5 = RC_WARN + 0x015
    """ The 6th handle in the handle area references a transient object or
    session that is not loaded
    """

    REFERENCE_H6 = RC_WARN + 0x016
    """ The 7th handle in the handle area references a transient object or
    session that is not loaded
    """

    REFERENCE_S0 = RC_WARN + 0x018
    """ The 1st authorization session handle references a session that is
    not loaded
    """

    REFERENCE_S1 = RC_WARN + 0x019
    """ The 2nd authorization session handle references a session that is
    not loaded
    """

    REFERENCE_S2 = RC_WARN + 0x01A
    """ The 3rd authorization session handle references a session that is
    not loaded
    """

    REFERENCE_S3 = RC_WARN + 0x01B
    """ The 4th authorization session handle references a session that is
    not loaded
    """

    REFERENCE_S4 = RC_WARN + 0x01C
    """ The 5th session handle references a session that is not loaded """

    REFERENCE_S5 = RC_WARN + 0x01D
    """ The 6th session handle references a session that is not loaded """

    REFERENCE_S6 = RC_WARN + 0x01E
    """ The 7th authorization session handle references a session that is
    not loaded
    """

    NV_RATE = RC_WARN + 0x020
    """ The TPM is rate-limiting accesses to prevent wearout of NV """

    LOCKOUT = RC_WARN + 0x021
    """ Authorizations for objects subject to DA protection are not allowed
    at this time because the TPM is in DA lockout mode
    """

    RETRY = RC_WARN + 0x022
    """ The TPM was not able to start the command """

    NV_UNAVAILABLE = RC_WARN + 0x023
    """ The command may require writing of NV and NV is not current accessible """

    NOT_USED = RC_WARN + 0x7F
    """ This value is reserved and shall not be returned by the TPM """

    P = 0x040
    """ Add to a parameter-related error """

    S = 0x800
    """ Add to a session-related error """

    _1 = 0x100
    """ Add to a parameter-, handle-, or session-related error """

    _2 = 0x200
    """ Add to a parameter-, handle-, or session-related error """

    _3 = 0x300
    """ Add to a parameter-, handle-, or session-related error """

    _4 = 0x400
    """ Add to a parameter-, handle-, or session-related error """

    _5 = 0x500
    """ Add to a parameter-, handle-, or session-related error """

    _6 = 0x600
    """ Add to a parameter-, handle-, or session-related error """

    _7 = 0x700
    """ Add to a parameter-, handle-, or session-related error """

    _8 = 0x800
    """ Add to a parameter-related error """

    _9 = 0x900
    """ Add to a parameter-related error """

    A = 0xA00
    """ Add to a parameter-related error """

    B = 0xB00
    """ Add to a parameter-related error """

    C = 0xC00
    """ Add to a parameter-related error """

    D = 0xD00
    """ Add to a parameter-related error """

    E = 0xE00
    """ Add to a parameter-related error """

    F = 0xF00
    """ Add to a parameter-related error """

    N_MASK = 0xF00
    """ Number mask """

    TSS_TCP_BAD_HANDSHAKE_RESP = 0x40280001
    """ Response buffer returned by the TPM is too short """

    TSS_TCP_SERVER_TOO_OLD = 0x40280002
    """ Too old TCP server version """

    TSS_TCP_BAD_ACK = 0x40280003
    """ Bad ack from the TCP end point """

    TSS_TCP_BAD_RESP_LEN = 0x40280004
    """ Wrong length of the response buffer returned by the TPM """

    TSS_TCP_UNEXPECTED_STARTUP_RESP = 0x40280005
    """ TPM2_Startup returned unexpected response code """

    TSS_TCP_INVALID_SIZE_TAG = 0x40280006
    """ Invalid size tag in the TPM response TCP packet """

    TSS_TCP_DISCONNECTED = 0x40280007
    """ TPM over TCP device is not connected """

    TSS_DISPATCH_FAILED = 0x40280010
    """ General TPM command dispatch failure """

    TSS_SEND_OP_FAILED = 0x40280011
    """ Sending data to TPM failed """

    TSS_RESP_BUF_TOO_SHORT = 0x40280021
    """ Response buffer returned by the TPM is too short """

    TSS_RESP_BUF_INVALID_SESSION_TAG = 0x40280022
    """ Invalid tag in the response buffer returned by the TPM """

    TSS_RESP_BUF_INVALID_SIZE = 0x40280023
    """ Inconsistent TPM response parameters size """

    TBS_COMMAND_BLOCKED = 0x80280400
    """ Windows TBS error TPM_E_COMMAND_BLOCKED """

    TBS_INVALID_HANDLE = 0x80280401
    """ Windows TBS error TPM_E_INVALID_HANDLE """

    TBS_DUPLICATE_V_HANDLE = 0x80280402
    """ Windows TBS error TPM_E_DUPLICATE_VHANDLE """

    TBS_EMBEDDED_COMMAND_BLOCKED = 0x80280403
    """ Windows TBS error TPM_E_EMBEDDED_COMMAND_BLOCKED """

    TBS_EMBEDDED_COMMAND_UNSUPPORTED = 0x80280404
    """ Windows TBS error TPM_E_EMBEDDED_COMMAND_UNSUPPORTED """

    TBS_UNKNOWN_ERROR = 0x80284000
    """ Windows TBS returned success but empty response buffer """

    TBS_INTERNAL_ERROR = 0x80284001
    """ Windows TBS error TBS_E_INTERNAL_ERROR """

    TBS_BAD_PARAMETER = 0x80284002
    """ Windows TBS error TBS_E_BAD_PARAMETER """

    TBS_INVALID_OUTPUT_POINTER = 0x80284003
    """ Windows TBS error TBS_E_INVALID_OUTPUT_POINTER """

    TBS_INVALID_CONTEXT = 0x80284004
    """ Windows TBS error TBS_E_INVALID_CONTEXT """

    TBS_INSUFFICIENT_BUFFER = 0x80284005
    """ Windows TBS error TBS_E_INSUFFICIENT_BUFFER """

    TBS_IO_ERROR = 0x80284006
    """ Windows TBS error TBS_E_IOERROR """

    TBS_INVALID_CONTEXT_PARAM = 0x80284007
    """ Windows TBS error TBS_E_INVALID_CONTEXT_PARAM """

    TBS_SERVICE_NOT_RUNNING = 0x80284008
    """ Windows TBS error TBS_E_SERVICE_NOT_RUNNING """

    TBS_TOO_MANY_CONTEXTS = 0x80284009
    """ Windows TBS error TBS_E_TOO_MANY_TBS_CONTEXTS """

    TBS_TOO_MANY_RESOURCES = 0x8028400A
    """ Windows TBS error TBS_E_TOO_MANY_TBS_RESOURCES """

    TBS_SERVICE_START_PENDING = 0x8028400B
    """ Windows TBS error TBS_E_SERVICE_START_PENDING """

    TBS_PPI_NOT_SUPPORTED = 0x8028400C
    """ Windows TBS error TBS_E_PPI_NOT_SUPPORTED """

    TBS_COMMAND_CANCELED = 0x8028400D
    """ Windows TBS error TBS_E_COMMAND_CANCELED """

    TBS_BUFFER_TOO_LARGE = 0x8028400E
    """ Windows TBS error TBS_E_BUFFER_TOO_LARGE """

    TBS_TPM_NOT_FOUND = 0x8028400F
    """ Windows TBS error TBS_E_TPM_NOT_FOUND """

    TBS_SERVICE_DISABLED = 0x80284010
    """ Windows TBS error TBS_E_SERVICE_DISABLED """

    TBS_ACCESS_DENIED = 0x80284012
    """ Windows TBS error TBS_E_ACCESS_DENIED """

    TBS_PPI_FUNCTION_NOT_SUPPORTED = 0x80284014
    """ Windows TBS error TBS_E_PPI_FUNCTION_UNSUPPORTED """

    TBS_OWNER_AUTH_NOT_FOUND = 0x80284015
    """ Windows TBS error TBS_E_OWNERAUTH_NOT_FOUND """
# enum TPM_RC
    
class TPM_CLOCK_ADJUST(IntFlag): # INT8
    """ A TPM_CLOCK_ADJUST value is used to change the rate at which the TPM
    internal oscillator is divided. A change to the divider will change the
    rate at which Clock and Time change.
    """

    COARSE_SLOWER = -3
    """ Slow the Clock update rate by one coarse adjustment step. """

    MEDIUM_SLOWER = -2
    """ Slow the Clock update rate by one medium adjustment step. """

    FINE_SLOWER = -1
    """ Slow the Clock update rate by one fine adjustment step. """

    NO_CHANGE = 0
    """ No change to the Clock update rate. """

    FINE_FASTER = 1
    """ Speed the Clock update rate by one fine adjustment step. """

    MEDIUM_FASTER = 2
    """ Speed the Clock update rate by one medium adjustment step. """

    COARSE_FASTER = 3
    """ Speed the Clock update rate by one coarse adjustment step. """
# enum TPM_CLOCK_ADJUST

class TPM_EO(IntFlag): # UINT16
    """ Table 18 Definition of (UINT16) TPM_EO Constants [IN/OUT] """

    EQ = 0x0000
    """ A = B """

    NEQ = 0x0001
    """ A B """

    SIGNED_GT = 0x0002
    """ A ˃ B signed """

    UNSIGNED_GT = 0x0003
    """ A ˃ B unsigned """

    SIGNED_LT = 0x0004
    """ A ˂ B signed """

    UNSIGNED_LT = 0x0005
    """ A ˂ B unsigned """

    SIGNED_GE = 0x0006
    """ A B signed """

    UNSIGNED_GE = 0x0007
    """ A B unsigned """

    SIGNED_LE = 0x0008
    """ A B signed """

    UNSIGNED_LE = 0x0009
    """ A B unsigned """

    BITSET = 0x000A
    """ All bits SET in B are SET in A. ((A∧B)=B) """

    BITCLEAR = 0x000B
    """ All bits SET in B are CLEAR in A. ((A∧B)=0) """
# enum TPM_EO
    
class TPM_ST(IntFlag): # UINT16
    """ Structure tags are used to disambiguate structures. They are 16-bit
    values with the most significant bit SET so that they do not overlap
    TPM_ALG_ID values. A single exception is made for the value associated
    with TPM_ST_RSP_COMMAND (0x00C4), which has the same value as the
    TPM_TAG_RSP_COMMAND tag from earlier versions of this specification.
    This value is used when the TPM is compatible with a previous TPM
    specification and the TPM cannot determine which family of response code
    to return because the command tag is not valid.
    """

    RSP_COMMAND = 0x00C4
    """ Tag value for a response; used when there is an error in the tag.
    This is also the value returned from a TPM 1.2 when an error occurs.
    This value is used in this specification because an error in the command
    tag may prevent determination of the family. When this tag is used in
    the response, the response code will be TPM_RC_BAD_TAG (0 1E16), which
    has the same numeric value as the TPM 1.2 response code for TPM_BADTAG.
    NOTE In a previously published version of this specification,
    TPM_RC_BAD_TAG was incorrectly assigned a value of 0x030 instead of 30
    (0x01e). Some implementations my return the old value instead of the new
    value.
    """

    NULL = 0X8000
    """ No structure type specified """

    NO_SESSIONS = 0x8001
    """ Tag value for a command/response for a command defined in this
    specification; indicating that the command/response has no attached
    sessions and no authorizationSize/parameterSize value is present
    If the responseCode from the TPM is not TPM_RC_SUCCESS, then the
    response tag shall have this value.
    """

    SESSIONS = 0x8002
    """ Tag value for a command/response for a command defined in this
    specification; indicating that the command/response has one or more
    attached sessions and the authorizationSize/parameterSize field is present
    """

    ATTEST_NV = 0x8014
    """ Tag for an attestation structure """

    ATTEST_COMMAND_AUDIT = 0x8015
    """ Tag for an attestation structure """

    ATTEST_SESSION_AUDIT = 0x8016
    """ Tag for an attestation structure """

    ATTEST_CERTIFY = 0x8017
    """ Tag for an attestation structure """

    ATTEST_QUOTE = 0x8018
    """ Tag for an attestation structure """

    ATTEST_TIME = 0x8019
    """ Tag for an attestation structure """

    ATTEST_CREATION = 0x801A
    """ Tag for an attestation structure """

    ATTEST_NV_DIGEST = 0x801C
    """ Tag for an attestation structure """

    CREATION = 0x8021
    """ Tag for a ticket type """

    VERIFIED = 0x8022
    """ Tag for a ticket type """

    AUTH_SECRET = 0x8023
    """ Tag for a ticket type """

    HASHCHECK = 0x8024
    """ Tag for a ticket type """

    AUTH_SIGNED = 0x8025
    """ Tag for a ticket type """

    FU_MANIFEST = 0x8029
    """ Tag for a structure describing a Field Upgrade Policy """
# enum TPM_ST

class TPM_SU(IntFlag): # UINT16
    """ These values are used in TPM2_Startup() to indicate the shutdown and
    startup mode. The defined startup sequences are:
    """

    CLEAR = 0x0000
    """ On TPM2_Shutdown(), indicates that the TPM should prepare for loss
    of power and save state required for an orderly startup (TPM Reset).
    on TPM2_Startup(), indicates that the TPM should perform TPM Reset or
    TPM Restart
    """

    STATE = 0x0001
    """ On TPM2_Shutdown(), indicates that the TPM should prepare for loss
    of power and save state required for an orderly startup (TPM Restart or
    TPM Resume)
    on TPM2_Startup(), indicates that the TPM should restore the state saved
    by TPM2_Shutdown(TPM_SU_STATE)
    """
# enum TPM_SU

class TPM_SE(IntFlag): # UINT8
    """ This type is used in TPM2_StartAuthSession() to indicate the type of
    the session to be created.
    """

    HMAC = 0x00

    POLICY = 0x01

    TRIAL = 0x03
    """ The policy session is being used to compute the policyHash and not
    for command authorization.
    This setting modifies some policy commands and prevents session from
    being used to authorize a command.
    """
# enum TPM_SE

class TPM_CAP(IntFlag): # UINT32
    """ The TPM_CAP values are used in TPM2_GetCapability() to select the
    type of the value to be returned. The format of the response varies
    according to the type of the value.
    """

    FIRST = 0x00000000

    ALGS = 0x00000000
    """ TPML_ALG_PROPERTY """

    HANDLES = 0x00000001
    """ TPML_HANDLE """

    COMMANDS = 0x00000002
    """ TPML_CCA """

    PP_COMMANDS = 0x00000003
    """ TPML_CC """

    AUDIT_COMMANDS = 0x00000004
    """ TPML_CC """

    PCRS = 0x00000005
    """ TPML_PCR_SELECTION """

    TPM_PROPERTIES = 0x00000006
    """ TPML_TAGGED_TPM_PROPERTY """

    PCR_PROPERTIES = 0x00000007
    """ TPML_TAGGED_PCR_PROPERTY """

    ECC_CURVES = 0x00000008
    """ TPML_ECC_CURVE """

    AUTH_POLICIES = 0x00000009
    """ TPML_TAGGED_POLICY """

    ACT = 0x0000000A
    """ TPML_ACT_DATA """

    LAST = 0x0000000A

    VENDOR_PROPERTY = 0x00000100
    """ Manufacturer-specific values """
# enum TPM_CAP
    

class TPM_PT(IntFlag): # UINT32
    """ The TPM_PT constants are used in TPM2_GetCapability(capability =
    TPM_CAP_TPM_PROPERTIES) to indicate the property being selected or returned.
    """

    NONE = 0x00000000
    """ Indicates no property type """

    PT_GROUP = 0x00000100
    """ The number of properties in each group.
    NOTE The first group with any properties is group 1 (PT_GROUP * 1).
    Group 0 is reserved.
    """

    PT_FIXED = PT_GROUP * 1
    """ The group of fixed properties returned as TPMS_TAGGED_PROPERTY
    The values in this group are only changed due to a firmware change in
    the TPM.
    """

    FAMILY_INDICATOR = PT_FIXED + 0
    """ A 4-octet character string containing the TPM Family value
    (TPM_SPEC_FAMILY)
    """

    LEVEL = PT_FIXED + 1
    """ The level of the specification
    NOTE 1 For this specification, the level is zero.
    NOTE 2 The level is on the title page of the specification.
    """

    REVISION = PT_FIXED + 2
    """ The specification Revision times 100
    EXAMPLE Revision 01.01 would have a value of 101.
    NOTE The Revision value is on the title page of the specification.
    """

    DAY_OF_YEAR = PT_FIXED + 3
    """ The specification day of year using TCG calendar
    EXAMPLE November 15, 2010, has a day of year value of 319 (0000013F16).
    NOTE The specification date is on the title page of the specification or
    errata (see 6.1).
    """

    YEAR = PT_FIXED + 4
    """ The specification year using the CE
    EXAMPLE The year 2010 has a value of 000007DA16.
    NOTE The specification date is on the title page of the specification or
    errata (see 6.1).
    """

    MANUFACTURER = PT_FIXED + 5
    """ The vendor ID unique to each TPM manufacturer """

    VENDOR_STRING_1 = PT_FIXED + 6
    """ The first four characters of the vendor ID string
    NOTE When the vendor string is fewer than 16 octets, the additional
    property values do not have to be present. A vendor string of 4 octets
    can be represented in one 32-bit value and no null terminating character
    is required.
    """

    VENDOR_STRING_2 = PT_FIXED + 7
    """ The second four characters of the vendor ID string """

    VENDOR_STRING_3 = PT_FIXED + 8
    """ The third four characters of the vendor ID string """

    VENDOR_STRING_4 = PT_FIXED + 9
    """ The fourth four characters of the vendor ID sting """

    VENDOR_TPM_TYPE = PT_FIXED + 10
    """ Vendor-defined value indicating the TPM model """

    FIRMWARE_VERSION_1 = PT_FIXED + 11
    """ The most-significant 32 bits of a TPM vendor-specific value
    indicating the version number of the firmware. See 10.12.2 and 10.12.12.
    """

    FIRMWARE_VERSION_2 = PT_FIXED + 12
    """ The least-significant 32 bits of a TPM vendor-specific value
    indicating the version number of the firmware. See 10.12.2 and 10.12.12.
    """

    INPUT_BUFFER = PT_FIXED + 13
    """ The maximum size of a parameter (typically, a TPM2B_MAX_BUFFER) """

    HR_TRANSIENT_MIN = PT_FIXED + 14
    """ The minimum number of transient objects that can be held in TPM RAM
    NOTE This minimum shall be no less than the minimum value required by
    the platform-specific specification to which the TPM is built.
    """

    HR_PERSISTENT_MIN = PT_FIXED + 15
    """ The minimum number of persistent objects that can be held in TPM NV memory
    NOTE This minimum shall be no less than the minimum value required by
    the platform-specific specification to which the TPM is built.
    """

    HR_LOADED_MIN = PT_FIXED + 16
    """ The minimum number of authorization sessions that can be held in TPM
    RAM
    NOTE This minimum shall be no less than the minimum value required by
    the platform-specific specification to which the TPM is built.
    """

    ACTIVE_SESSIONS_MAX = PT_FIXED + 17
    """ The number of authorization sessions that may be active at a time
    A session is active when it has a context associated with its handle.
    The context may either be in TPM RAM or be context saved.
    NOTE This value shall be no less than the minimum value required by the
    platform-specific specification to which the TPM is built.
    """

    PCR_COUNT = PT_FIXED + 18
    """ The number of PCR implemented
    NOTE This number is determined by the defined attributes, not the number
    of PCR that are populated.
    """

    PCR_SELECT_MIN = PT_FIXED + 19
    """ The minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect
    NOTE This value is not determined by the number of PCR implemented but
    by the number of PCR required by the platform-specific specification
    with which the TPM is compliant or by the implementer if not adhering to
    a platform-specific specification.
    """

    CONTEXT_GAP_MAX = PT_FIXED + 20
    """ The maximum allowed difference (unsigned) between the contextID
    values of two saved session contexts
    This value shall be 2n-1, where n is at least 16.
    """

    NV_COUNTERS_MAX = PT_FIXED + 22
    """ The maximum number of NV Indexes that are allowed to have the
    TPM_NT_COUNTER attribute
    NOTE 1 It is allowed for this value to be larger than the number of NV
    Indexes that can be defined. This would be indicative of a TPM
    implementation that did not use different implementation technology for
    different NV Index types.
    NOTE 2 The value zero indicates that there is no fixed maximum. The
    number of counter indexes is determined by the available NV memory pool.
    """

    NV_INDEX_MAX = PT_FIXED + 23
    """ The maximum size of an NV Index data area """

    MEMORY = PT_FIXED + 24
    """ A TPMA_MEMORY indicating the memory management method for the TPM """

    CLOCK_UPDATE = PT_FIXED + 25
    """ Interval, in milliseconds, between updates to the copy of
    TPMS_CLOCK_INFO.clock in NV
    """

    CONTEXT_HASH = PT_FIXED + 26
    """ The algorithm used for the integrity HMAC on saved contexts and for
    hashing the fuData of TPM2_FirmwareRead()
    """

    CONTEXT_SYM = PT_FIXED + 27
    """ TPM_ALG_ID, the algorithm used for encryption of saved contexts """

    CONTEXT_SYM_SIZE = PT_FIXED + 28
    """ TPM_KEY_BITS, the size of the key used for encryption of saved contexts """

    ORDERLY_COUNT = PT_FIXED + 29
    """ The modulus - 1 of the count for NV update of an orderly counter
    The returned value is MAX_ORDERLY_COUNT.
    This will have a value of 2N 1 where 1 N 32
    NOTE 1 An orderly counter is an NV Index with an TPM_NT of
    TPM_NV_COUNTER and TPMA_NV_ORDERLY SET.
    NOTE 2 When the low-order bits of a counter equal this value, an NV
    write occurs on the next increment.
    """

    MAX_COMMAND_SIZE = PT_FIXED + 30
    """ The maximum value for commandSize in a command """

    MAX_RESPONSE_SIZE = PT_FIXED + 31
    """ The maximum value for responseSize in a response """

    MAX_DIGEST = PT_FIXED + 32
    """ The maximum size of a digest that can be produced by the TPM """

    MAX_OBJECT_CONTEXT = PT_FIXED + 33
    """ The maximum size of an object context that will be returned by
    TPM2_ContextSave
    """

    MAX_SESSION_CONTEXT = PT_FIXED + 34
    """ The maximum size of a session context that will be returned by
    TPM2_ContextSave
    """

    PS_FAMILY_INDICATOR = PT_FIXED + 35
    """ Platform-specific family (a TPM_PS value)(see Table 25)
    NOTE The platform-specific values for the TPM_PT_PS parameters are in
    the relevant platform-specific specification. In the reference
    implementation, all of these values are 0.
    """

    PS_LEVEL = PT_FIXED + 36
    """ The level of the platform-specific specification """

    PS_REVISION = PT_FIXED + 37
    """ A platform specific value """

    PS_DAY_OF_YEAR = PT_FIXED + 38
    """ The platform-specific TPM specification day of year using TCG calendar
    EXAMPLE November 15, 2010, has a day of year value of 319 (0000013F16).
    """

    PS_YEAR = PT_FIXED + 39
    """ The platform-specific TPM specification year using the CE
    EXAMPLE The year 2010 has a value of 000007DA16.
    """

    SPLIT_MAX = PT_FIXED + 40
    """ The number of split signing operations supported by the TPM """

    TOTAL_COMMANDS = PT_FIXED + 41
    """ Total number of commands implemented in the TPM """

    LIBRARY_COMMANDS = PT_FIXED + 42
    """ Number of commands from the TPM library that are implemented """

    VENDOR_COMMANDS = PT_FIXED + 43
    """ Number of vendor commands that are implemented """

    NV_BUFFER_MAX = PT_FIXED + 44
    """ The maximum data size in one NV write, NV read, NV extend, or NV
    certify command
    """

    MODES = PT_FIXED + 45
    """ A TPMA_MODES value, indicating that the TPM is designed for these modes. """

    MAX_CAP_BUFFER = PT_FIXED + 46
    """ The maximum size of a TPMS_CAPABILITY_DATA structure returned in
    TPM2_GetCapability().
    """

    PT_VAR = PT_GROUP * 2
    """ The group of variable properties returned as TPMS_TAGGED_PROPERTY
    The properties in this group change because of a Protected Capability
    other than a firmware update. The values are not necessarily persistent
    across all power transitions.
    """

    PERMANENT = PT_VAR + 0
    """ TPMA_PERMANENT """

    STARTUP_CLEAR = PT_VAR + 1
    """ TPMA_STARTUP_CLEAR """

    HR_NV_INDEX = PT_VAR + 2
    """ The number of NV Indexes currently defined """

    HR_LOADED = PT_VAR + 3
    """ The number of authorization sessions currently loaded into TPM RAM """

    HR_LOADED_AVAIL = PT_VAR + 4
    """ The number of additional authorization sessions, of any type, that
    could be loaded into TPM RAM
    This value is an estimate. If this value is at least 1, then at least
    one authorization session of any type may be loaded. Any command that
    changes the RAM memory allocation can make this estimate invalid.
    NOTE A valid implementation may return 1 even if more than one
    authorization session would fit into RAM.
    """

    HR_ACTIVE = PT_VAR + 5
    """ The number of active authorization sessions currently being tracked
    by the TPM
    This is the sum of the loaded and saved sessions.
    """

    HR_ACTIVE_AVAIL = PT_VAR + 6
    """ The number of additional authorization sessions, of any type, that
    could be created
    This value is an estimate. If this value is at least 1, then at least
    one authorization session of any type may be created. Any command that
    changes the RAM memory allocation can make this estimate invalid.
    NOTE A valid implementation may return 1 even if more than one
    authorization session could be created.
    """

    HR_TRANSIENT_AVAIL = PT_VAR + 7
    """ Estimate of the number of additional transient objects that could be
    loaded into TPM RAM
    This value is an estimate. If this value is at least 1, then at least
    one object of any type may be loaded. Any command that changes the
    memory allocation can make this estimate invalid.
    NOTE A valid implementation may return 1 even if more than one transient
    object would fit into RAM.
    """

    HR_PERSISTENT = PT_VAR + 8
    """ The number of persistent objects currently loaded into TPM NV memory """

    HR_PERSISTENT_AVAIL = PT_VAR + 9
    """ The number of additional persistent objects that could be loaded
    into NV memory
    This value is an estimate. If this value is at least 1, then at least
    one object of any type may be made persistent. Any command that changes
    the NV memory allocation can make this estimate invalid.
    NOTE A valid implementation may return 1 even if more than one
    persistent object would fit into NV memory.
    """

    NV_COUNTERS = PT_VAR + 10
    """ The number of defined NV Indexes that have NV the TPM_NT_COUNTER attribute """

    NV_COUNTERS_AVAIL = PT_VAR + 11
    """ The number of additional NV Indexes that can be defined with their
    TPM_NT of TPM_NV_COUNTER and the TPMA_NV_ORDERLY attribute SET
    This value is an estimate. If this value is at least 1, then at least
    one NV Index may be created with a TPM_NT of TPM_NV_COUNTER and the
    TPMA_NV_ORDERLY attributes. Any command that changes the NV memory
    allocation can make this estimate invalid.
    NOTE A valid implementation may return 1 even if more than one NV
    counter could be defined.
    """

    ALGORITHM_SET = PT_VAR + 12
    """ Code that limits the algorithms that may be used with the TPM """

    LOADED_CURVES = PT_VAR + 13
    """ The number of loaded ECC curves """

    LOCKOUT_COUNTER = PT_VAR + 14
    """ The current value of the lockout counter (failedTries) """

    MAX_AUTH_FAIL = PT_VAR + 15
    """ The number of authorization failures before DA lockout is invoked """

    LOCKOUT_INTERVAL = PT_VAR + 16
    """ The number of seconds before the value reported by
    TPM_PT_LOCKOUT_COUNTER is decremented
    """

    LOCKOUT_RECOVERY = PT_VAR + 17
    """ The number of seconds after a lockoutAuth failure before use of
    lockoutAuth may be attempted again
    """

    NV_WRITE_RECOVERY = PT_VAR + 18
    """ Number of milliseconds before the TPM will accept another command
    that will modify NV
    This value is an approximation and may go up or down over time.
    """

    AUDIT_COUNTER_0 = PT_VAR + 19
    """ The high-order 32 bits of the command audit counter """

    AUDIT_COUNTER_1 = PT_VAR + 20
    """ The low-order 32 bits of the command audit counter """
# enum TPM_PT

class TPM_PT_PCR(IntFlag): # UINT32
    """ The TPM_PT_PCR constants are used in TPM2_GetCapability() to
    indicate the property being selected or returned. The PCR properties can
    be read when capability == TPM_CAP_PCR_PROPERTIES. If there is no
    property that corresponds to the value of property, the next higher
    value is returned, if it exists.
    """

    FIRST = 0x00000000
    """ Bottom of the range of TPM_PT_PCR properties """

    SAVE = 0x00000000
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and
    restored by TPM_SU_STATE
    """

    EXTEND_L0 = 0x00000001
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    extended from locality 0
    This property is only present if a locality other than 0 is implemented.
    """

    RESET_L0 = 0x00000002
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    by TPM2_PCR_Reset() from locality 0
    """

    EXTEND_L1 = 0x00000003
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    extended from locality 1
    This property is only present if locality 1 is implemented.
    """

    RESET_L1 = 0x00000004
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    by TPM2_PCR_Reset() from locality 1
    This property is only present if locality 1 is implemented.
    """

    EXTEND_L2 = 0x00000005
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    extended from locality 2
    This property is only present if localities 1 and 2 are implemented.
    """

    RESET_L2 = 0x00000006
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    by TPM2_PCR_Reset() from locality 2
    This property is only present if localities 1 and 2 are implemented.
    """

    EXTEND_L3 = 0x00000007
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    extended from locality 3
    This property is only present if localities 1, 2, and 3 are implemented.
    """

    RESET_L3 = 0x00000008
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    by TPM2_PCR_Reset() from locality 3
    This property is only present if localities 1, 2, and 3 are implemented.
    """

    EXTEND_L4 = 0x00000009
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be
    extended from locality 4
    This property is only present if localities 1, 2, 3, and 4 are implemented.
    """

    RESET_L4 = 0x0000000A
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset
    by TPM2_PCR_Reset() from locality 4
    This property is only present if localities 1, 2, 3, and 4 are implemented.
    """

    NO_INCREMENT = 0x00000011
    """ A SET bit in the TPMS_PCR_SELECT indicates that modifications to
    this PCR (reset or Extend) will not increment the pcrUpdateCounter
    """

    DRTM_RESET = 0x00000012
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by
    a D-RTM event
    These PCR are reset to -1 on TPM2_Startup() and reset to 0 on a
    _TPM_Hash_End event following a _TPM_Hash_Start event.
    """

    POLICY = 0x00000013
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR is
    controlled by policy
    This property is only present if the TPM supports policy control of a PCR.
    """

    AUTH = 0x00000014
    """ A SET bit in the TPMS_PCR_SELECT indicates that the PCR is
    controlled by an authorization value
    This property is only present if the TPM supports authorization control
    of a PCR.
    """

    LAST = 0x00000014
    """ Top of the range of TPM_PT_PCR properties of the implementation
    If the TPM receives a request for a PCR property with a value larger
    than this, the TPM will return a zero length list and set the moreData
    parameter to NO.
    NOTE This is an implementation-specific value. The value shown reflects
    the reference code implementation.
    """
# enum TPM_PT_PCR

class TPM_PS(IntFlag): # UINT32
    """ The platform values in Table 25 are used for the
    TPM_PT_PS_FAMILY_INDICATOR.
    """

    MAIN = 0x00000000
    """ Not platform specific """

    PC = 0x00000001
    """ PC Client """

    PDA = 0x00000002
    """ PDA (includes all mobile devices that are not specifically cell phones) """

    CELL_PHONE = 0x00000003
    """ Cell Phone """

    SERVER = 0x00000004
    """ Server WG """

    PERIPHERAL = 0x00000005
    """ Peripheral WG """

    TSS = 0x00000006
    """ TSS WG (deprecated) """

    STORAGE = 0x00000007
    """ Storage WG """

    AUTHENTICATION = 0x00000008
    """ Authentication WG """

    EMBEDDED = 0x00000009
    """ Embedded WG """

    HARDCOPY = 0x0000000A
    """ Hardcopy WG """

    INFRASTRUCTURE = 0x0000000B
    """ Infrastructure WG (deprecated) """

    VIRTUALIZATION = 0x0000000C
    """ Virtualization WG """

    TNC = 0x0000000D
    """ Trusted Network Connect WG (deprecated) """

    MULTI_TENANT = 0x0000000E
    """ Multi-tenant WG (deprecated) """

    TC = 0x0000000F
    """ Technical Committee (deprecated) """
# enum TPM_PS

class TPM_HT(IntFlag): # UINT8
    """ The 32-bit handle space is divided into 256 regions of equal size
    with 224 values in each. Each of these ranges represents a handle type.
    """

    PCR = 0x00
    """ PCR consecutive numbers, starting at 0, that reference the PCR registers
    A platform-specific specification will set the minimum number of PCR and
    an implementation may have more.
    """

    NV_INDEX = 0x01
    """ NV Index assigned by the caller """

    HMAC_SESSION = 0x02
    """ HMAC Authorization Session assigned by the TPM when the session is created """

    LOADED_SESSION = 0x02
    """ Loaded Authorization Session used only in the context of TPM2_GetCapability
    This type references both loaded HMAC and loaded policy authorization sessions.
    """

    POLICY_SESSION = 0x03
    """ Policy Authorization Session assigned by the TPM when the session is
    created
    """

    SAVED_SESSION = 0x03
    """ Saved Authorization Session used only in the context of TPM2_GetCapability
    This type references saved authorization session contexts for which the
    TPM is maintaining tracking information.
    """

    PERMANENT = 0x40
    """ Permanent Values assigned by this specification in Table 28 """

    TRANSIENT = 0x80
    """ Transient Objects assigned by the TPM when an object is loaded into
    transient-object memory or when a persistent object is converted to a
    transient object
    """

    PERSISTENT = 0x81
    """ Persistent Objects assigned by the TPM when a loaded transient
    object is made persistent
    """

    AC = 0x90
    """ Attached Component handle for an Attached Component. """
# enum TPM_HT

class TPM_RH(IntFlag): # TPM_HANDLE
    """ Table 28 lists the architecturally defined handles that cannot be
    changed. The handles include authorization handles, and special handles.
    """

    FIRST = 0x40000000

    SRK = 0x40000000
    """ Not used1 """

    OWNER = 0x40000001
    """ Handle references the Storage Primary Seed (SPS), the ownerAuth, and
    the ownerPolicy
    """

    REVOKE = 0x40000002
    """ Not used1 """

    TRANSPORT = 0x40000003
    """ Not used1 """

    OPERATOR = 0x40000004
    """ Not used1 """

    ADMIN = 0x40000005
    """ Not used1 """

    EK = 0x40000006
    """ Not used1 """

    NULL = 0x40000007
    """ A handle associated with the null hierarchy, an EmptyAuth authValue,
    and an Empty Policy authPolicy.
    """

    UNASSIGNED = 0x40000008
    """ Value reserved to the TPM to indicate a handle location that has not
    been initialized or assigned
    """

    PW = 0x40000009
    """ Authorization value used to indicate a password authorization session """
    """ Deprecated: use PW instead """
    RS_PW = 0x40000009

    LOCKOUT = 0x4000000A
    """ References the authorization associated with the dictionary attack
    lockout reset
    """

    ENDORSEMENT = 0x4000000B
    """ References the Endorsement Primary Seed (EPS), endorsementAuth, and
    endorsementPolicy
    """

    PLATFORM = 0x4000000C
    """ References the Platform Primary Seed (PPS), platformAuth, and
    platformPolicy
    """

    PLATFORM_NV = 0x4000000D
    """ For phEnableNV """

    AUTH_00 = 0x40000010
    """ Start of a range of authorization values that are vendor-specific. A
    TPM may support any of the values in this range as are needed for
    vendor-specific purposes.
    Disabled if ehEnable is CLEAR.
    NOTE Any includes none.
    """

    AUTH_FF = 0x4000010F
    """ End of the range of vendor-specific authorization values. """

    ACT_0 = 0x40000110
    """ Start of the range of authenticated timers """

    ACT_F = 0x4000011F
    """ End of the range of authenticated timers """

    LAST = 0x4000011F
    """ The top of the reserved handle area
    This is set to allow TPM2_GetCapability() to know where to stop. It may
    vary as implementations add to the permanent handle area.
    """
# enum TPM_RH
    
class TPM_NT(IntFlag): # UINT32
    """ This table lists the values of the TPM_NT field of a TPMA_NV. See
    Table 215 for usage.
    """

    ORDINARY = 0x0
    """ Ordinary contains data that is opaque to the TPM that can only be
    modified using TPM2_NV_Write().
    """

    COUNTER = 0x1
    """ Counter contains an 8-octet value that is to be used as a counter
    and can only be modified with TPM2_NV_Increment()
    """

    BITS = 0x2
    """ Bit Field contains an 8-octet value to be used as a bit field and
    can only be modified with TPM2_NV_SetBits().
    """

    EXTEND = 0x4
    """ Extend contains a digest-sized value used like a PCR. The Index can
    only be modified using TPM2_NV_Extend(). The extend will use the nameAlg
    of the Index.
    """

    PIN_FAIL = 0x8
    """ PIN Fail - contains pinCount that increments on a PIN authorization
    failure and a pinLimit
    """

    PIN_PASS = 0x9
    """ PIN Pass - contains pinCount that increments on a PIN authorization
    success and a pinLimit
    """
# enum TPM_NT

class TPM_AT(IntFlag): # UINT32
    """ These constants are used in TPM2_AC_GetCapability() to indicate the
    first tagged value returned from an attached component.
    """

    ANY = 0x00000000
    """ In a command, a non-specific request for AC information; in a
    response, indicates that outputData is not meaningful
    """

    ERROR = 0x00000001
    """ Indicates a TCG defined, device-specific error """

    PV1 = 0x00000002
    """ Indicates the most significant 32 bits of a pairing value for the AC """

    VEND = 0x80000000
    """ Value added to a TPM_AT to indicate a vendor-specific tag value """
# enum TPM_AT

class TPM_AE(IntFlag): # UINT32
    """ These constants are the TCG-defined error values returned by an AC. """

    NONE = 0x00000000
    """ In a command, a non-specific request for AC information; in a
    response, indicates that outputData is not meaningful
    """
# enum TPM_AE

class PLATFORM(IntFlag): # UINT32
    """ These values are readable with TPM2_GetCapability(). They are the
    TPM_PT_PS_xxx values.
    """

    FAMILY = TPM_SPEC.FAMILY

    LEVEL = TPM_SPEC.LEVEL

    VERSION = TPM_SPEC.VERSION

    YEAR = TPM_SPEC.YEAR

    DAY_OF_YEAR = TPM_SPEC.DAY_OF_YEAR
# enum PLATFORM

class Implementation(IntFlag): # UINT32
    """ This table contains a collection of values used in various parts of
    the reference code. The values shown are illustrative.
    """

    FIELD_UPGRADE_IMPLEMENTED = Logic.NO
    """ Temporary define """

    HASH_LIB = ImplementationConstants.Ossl
    """ Selection of the library that provides the basic hashing functions. """

    SYM_LIB = ImplementationConstants.Ossl
    """ Selection of the library that provides the low-level symmetric
    cryptography. Choices are determined by the vendor (See LibSupport.h for
    implications).
    """

    MATH_LIB = ImplementationConstants.Ossl
    """ Selection of the library that provides the big number math including
    ECC. Choices are determined by the vendor (See LibSupport.h for implications).
    """

    IMPLEMENTATION_PCR = 24
    """ The number of PCR in the TPM """

    PCR_SELECT_MAX = ((IMPLEMENTATION_PCR+7) // 8)

    PLATFORM_PCR = 24
    """ The number of PCR required by the relevant platform specification """

    PCR_SELECT_MIN = ((PLATFORM_PCR + 7) // 8)

    DRTM_PCR = 17
    """ The D-RTM PCR
    NOTE This value is not defined when the TPM does not implement D-RTM
    """

    HCRTM_PCR = 0
    """ The PCR that will receive the H-CRTM value at TPM2_Startup. This
    value should not be changed.
    """

    NUM_LOCALITIES = 5
    """ The number of localities supported by the TPM
    This is expected to be either 5 for a PC, or 1 for just about everything
    else.
    """

    MAX_HANDLE_NUM = 3
    """ The maximum number of handles in the handle area
    This should be produced by the Part 3 parser but is here for now.
    """

    MAX_ACTIVE_SESSIONS = 64
    """ The number of simultaneously active sessions that are supported by
    the TPM implementation
    """

    MAX_LOADED_SESSIONS = 3
    """ The number of sessions that the TPM may have in memory """

    MAX_SESSION_NUM = 3
    """ This is the current maximum value """

    MAX_LOADED_OBJECTS = 3
    """ The number of simultaneously loaded objects that are supported by
    the TPM; this number does not include the objects that may be placed in
    NV memory by TPM2_EvictControl().
    """

    MIN_EVICT_OBJECTS = 2
    """ The minimum number of evict objects supported by the TPM """

    NUM_POLICY_PCR_GROUP = 1
    """ Number of PCR groups that have individual policies """

    NUM_AUTHVALUE_PCR_GROUP = 1
    """ Number of PCR groups that have individual authorization values """

    MAX_CONTEXT_SIZE = 1264

    MAX_DIGEST_BUFFER = 1024

    MAX_NV_INDEX_SIZE = 2048
    """ Maximum data size allowed in an NV Index """

    MAX_NV_BUFFER_SIZE = 1024
    """ Maximum data size in one NV read or write command """

    MAX_CAP_BUFFER = 1024
    """ Maximum size of a capability buffer """

    NV_MEMORY_SIZE = 16384
    """ Size of NV memory in octets """

    MIN_COUNTER_INDICES = 8
    """ The TPM will not allocate a non-counter index if it would prevent
    allocation of this number of indices.
    """

    NUM_STATIC_PCR = 16

    MAX_ALG_LIST_SIZE = 64
    """ Number of algorithms that can be in a list """

    PRIMARY_SEED_SIZE = 32
    """ Size of the Primary Seed in octets """

    CONTEXT_ENCRYPT_ALGORITHM = TPM_ALG_ID.AES
    """ Context encryption algorithm
    Just use the root so that the macros in GpMacros.h will work correctly.
    """

    NV_CLOCK_UPDATE_INTERVAL = 12
    """ The update interval expressed as a power of 2 seconds
    A value of 12 is 4,096 seconds (~68 minutes).
    """

    NUM_POLICY_PCR = 1
    """ Number of PCR groups that allow policy/auth """

    MAX_COMMAND_SIZE = 4096
    """ Maximum size of a command """

    MAX_RESPONSE_SIZE = 4096
    """ Maximum size of a response """

    ORDERLY_BITS = 8
    """ Number between 1 and 32 inclusive """

    MAX_SYM_DATA = 128
    """ The maximum number of octets that may be in a sealed blob; 128 is
    the minimum allowed value
    """

    MAX_RNG_ENTROPY_SIZE = 64

    RAM_INDEX_SPACE = 512
    """ Number of bytes used for the RAM index space. If this is not large
    enough, it might not be possible to allocate orderly indices.
    """

    RSA_DEFAULT_PUBLIC_EXPONENT = 0x00010001
    """ 216 + 1 """

    ENABLE_PCR_NO_INCREMENT = Logic.YES
    """ Indicates if the TPM_PT_PCR_NO_INCREMENT group is implemented """

    CRT_FORMAT_RSA = Logic.YES

    VENDOR_COMMAND_COUNT = 0

    MAX_VENDOR_BUFFER_SIZE = 1024
    """ Maximum size of the vendor-specific buffer """

    MAX_DERIVATION_BITS = 8192
    """ L value for a derivation. This is the
    maximum number of bits allowed from an instantiation of a KDF-DRBG. This
    is size is OK because RSA keys are never derived keys
    """

    RSA_MAX_PRIME = (ImplementationConstants.MAX_RSA_KEY_BYTES // 2)

    RSA_PRIVATE_SIZE = (RSA_MAX_PRIME * 5)

    SIZE_OF_X509_SERIAL_NUMBER = 20

    PRIVATE_VENDOR_SPECIFIC_BYTES = RSA_PRIVATE_SIZE
    """ This is a vendor-specific value so it is in this vendor-speific
    table. When this is used, RSA_PRIVATE_SIZE will have been defined
    """
# enum Implementation

class TPM_HC(IntFlag): # TPM_HANDLE
    """ The definitions in Table 29 are used to define many of the interface
    data types.
    """

    HR_HANDLE_MASK = 0x00FFFFFF
    """ To mask off the HR """

    HR_RANGE_MASK = 0xFF000000
    """ To mask off the variable part """

    HR_SHIFT = 24

    HR_PCR = (TPM_HT.PCR << HR_SHIFT)

    HR_HMAC_SESSION = (TPM_HT.HMAC_SESSION << HR_SHIFT)

    HR_POLICY_SESSION = (TPM_HT.POLICY_SESSION << HR_SHIFT)

    HR_TRANSIENT = (TPM_HT.TRANSIENT << HR_SHIFT)

    HR_PERSISTENT = (TPM_HT.PERSISTENT << HR_SHIFT)

    HR_NV_INDEX = (TPM_HT.NV_INDEX << HR_SHIFT)

    HR_PERMANENT = (TPM_HT.PERMANENT << HR_SHIFT)

    PCR_FIRST = (HR_PCR + 0)
    """ First PCR """

    PCR_LAST = (PCR_FIRST + Implementation.IMPLEMENTATION_PCR-1)
    """ Last PCR """

    HMAC_SESSION_FIRST = (HR_HMAC_SESSION + 0)
    """ First HMAC session """

    HMAC_SESSION_LAST = (HMAC_SESSION_FIRST+Implementation.MAX_ACTIVE_SESSIONS-1)
    """ Last HMAC session """

    LOADED_SESSION_FIRST = HMAC_SESSION_FIRST
    """ Used in GetCapability """

    LOADED_SESSION_LAST = HMAC_SESSION_LAST
    """ Used in GetCapability """

    POLICY_SESSION_FIRST = (HR_POLICY_SESSION + 0)
    """ First policy session """

    POLICY_SESSION_LAST = (POLICY_SESSION_FIRST + Implementation.MAX_ACTIVE_SESSIONS-1)
    """ Last policy session """

    TRANSIENT_FIRST = (HR_TRANSIENT + 0)
    """ First transient object """

    ACTIVE_SESSION_FIRST = POLICY_SESSION_FIRST
    """ Used in GetCapability """

    ACTIVE_SESSION_LAST = POLICY_SESSION_LAST
    """ Used in GetCapability """

    TRANSIENT_LAST = (TRANSIENT_FIRST+Implementation.MAX_LOADED_OBJECTS-1)
    """ Last transient object """

    PERSISTENT_FIRST = (HR_PERSISTENT + 0)
    """ First persistent object """

    PERSISTENT_LAST = (PERSISTENT_FIRST + 0x00FFFFFF)
    """ Last persistent object """

    PLATFORM_PERSISTENT = (PERSISTENT_FIRST + 0x00800000)
    """ First platform persistent object """

    NV_INDEX_FIRST = (HR_NV_INDEX + 0)
    """ First allowed NV Index """

    NV_INDEX_LAST = (NV_INDEX_FIRST + 0x00FFFFFF)
    """ Last allowed NV Index """

    PERMANENT_FIRST = TPM_RH.FIRST

    PERMANENT_LAST = TPM_RH.LAST

    HR_NV_AC = ((TPM_HT.NV_INDEX << HR_SHIFT) + 0xD00000)
    """ AC aliased NV Index """

    NV_AC_FIRST = (HR_NV_AC + 0)
    """ First NV Index aliased to Attached Component """

    NV_AC_LAST = (HR_NV_AC + 0x0000FFFF)
    """ Last NV Index aliased to Attached Component """

    HR_AC = (TPM_HT.AC << HR_SHIFT)
    """ AC Handle """

    AC_FIRST = (HR_AC + 0)
    """ First Attached Component """

    AC_LAST = (HR_AC + 0x0000FFFF)
    """ Last Attached Component """
# enum TPM_HC
    
class TPMA_ALGORITHM(IntFlag): # UINT32
    """ This structure defines the attributes of an algorithm. """

    asymmetric = 0x1
    """ SET (1): an asymmetric algorithm with public and private portions
    CLEAR (0): not an asymmetric algorithm
    """

    symmetric = 0x2
    """ SET (1): a symmetric block cipher
    CLEAR (0): not a symmetric block cipher
    """

    hash = 0x4
    """ SET (1): a hash algorithm
    CLEAR (0): not a hash algorithm
    """

    object = 0x8
    """ SET (1): an algorithm that may be used as an object type
    CLEAR (0): an algorithm that is not used as an object type
    """

    signing = 0x100
    """ SET (1): a signing algorithm. The setting of asymmetric, symmetric,
    and hash will indicate the type of signing algorithm.
    CLEAR (0): not a signing algorithm
    """

    encrypting = 0x200
    """ SET (1): an encryption/decryption algorithm. The setting of
    asymmetric, symmetric, and hash will indicate the type of
    encryption/decryption algorithm.
    CLEAR (0): not an encryption/decryption algorithm
    """

    method = 0x400
    """ SET (1): a method such as a key derivative function (KDF)
    CLEAR (0): not a method
    """
# bitfield TPMA_ALGORITHM

class TPMA_OBJECT(IntFlag): # UINT32
    """ This attribute structure indicates an objects use, its authorization
    types, and its relationship to other objects.
    """

    fixedTPM = 0x2
    """ SET (1): The hierarchy of the object, as indicated by its Qualified
    Name, may not change.
    CLEAR (0): The hierarchy of the object may change as a result of this
    object or an ancestor key being duplicated for use in another hierarchy.
    NOTE fixedTPM does not indicate that key material resides on a single
    TPM (see sensitiveDataOrigin).
    """

    stClear = 0x4
    """ SET (1): Previously saved contexts of this object may not be loaded
    after Startup(CLEAR).
    CLEAR (0): Saved contexts of this object may be used after a
    Shutdown(STATE) and subsequent Startup().
    """

    fixedParent = 0x10
    """ SET (1): The parent of the object may not change.
    CLEAR (0): The parent of the object may change as the result of a
    TPM2_Duplicate() of the object.
    """

    sensitiveDataOrigin = 0x20
    """ SET (1): Indicates that, when the object was created with
    TPM2_Create() or TPM2_CreatePrimary(), the TPM generated all of the
    sensitive data other than the authValue.
    CLEAR (0): A portion of the sensitive data, other than the authValue,
    was provided by the caller.
    """

    userWithAuth = 0x40
    """ SET (1): Approval of USER role actions with this object may be with
    an HMAC session or with a password using the authValue of the object or
    a policy session.
    CLEAR (0): Approval of USER role actions with this object may only be
    done with a policy session.
    """

    adminWithPolicy = 0x80
    """ SET (1): Approval of ADMIN role actions with this object may only be
    done with a policy session.
    CLEAR (0): Approval of ADMIN role actions with this object may be with
    an HMAC session or with a password using the authValue of the object or
    a policy session.
    """

    noDA = 0x400
    """ SET (1): The object is not subject to dictionary attack protections.
    CLEAR (0): The object is subject to dictionary attack protections.
    """

    encryptedDuplication = 0x800
    """ SET (1): If the object is duplicated, then symmetricAlg shall not be
    TPM_ALG_NULL and newParentHandle shall not be TPM_RH_NULL.
    CLEAR (0): The object may be duplicated without an inner wrapper on the
    private portion of the object and the new parent may be TPM_RH_NULL.
    """

    restricted = 0x10000
    """ SET (1): Key usage is restricted to manipulate structures of known
    format; the parent of this key shall have restricted SET.
    CLEAR (0): Key usage is not restricted to use on special formats.
    """

    decrypt = 0x20000
    """ SET (1): The private portion of the key may be used to decrypt.
    CLEAR (0): The private portion of the key may not be used to decrypt.
    """

    sign = 0x40000
    """ SET (1): For a symmetric cipher object, the private portion of the
    key may be used to encrypt. For other objects, the private portion of
    the key may be used to sign.
    CLEAR (0): The private portion of the key may not be used to sign or encrypt.
    """

    encrypt = 0x40000
    """ Alias to the sign value. """

    x509sign = 0x80000
    """ SET (1): An asymmetric key that may not be used to sign with TPM2_Sign()
    CLEAR (0): A key that may be used with TPM2_Sign() if sign is SET
    NOTE: This attribute only has significance if sign is SET.
    """
# bitfield TPMA_OBJECT

class TPMA_SESSION(IntFlag): # UINT8
    """ This octet in each session is used to identify the session type,
    indicate its relationship to any handles in the command, and indicate
    its use in parameter encryption.
    """

    continueSession = 0x1
    """ SET (1): In a command, this setting indicates that the session is to
    remain active after successful completion of the command. In a response,
    it indicates that the session is still active. If SET in the command,
    this attribute shall be SET in the response.
    CLEAR (0): In a command, this setting indicates that the TPM should
    close the session and flush any related context when the command
    completes successfully. In a response, it indicates that the session is
    closed and the context is no longer active.
    This attribute has no meaning for a password authorization and the TPM
    will allow any setting of the attribute in the command and SET the
    attribute in the response.
    This attribute will only be CLEAR in one response for a logical session.
    If the attribute is CLEAR, the context associated with the session is no
    longer in use and the space is available. A session created after
    another session is ended may have the same handle but logically is not
    the same session.
    This attribute has no effect if the command does not complete successfully.
    """

    auditExclusive = 0x2
    """ SET (1): In a command, this setting indicates that the command
    should only be executed if the session is exclusive at the start of the
    command. In a response, it indicates that the session is exclusive. This
    setting is only allowed if the audit attribute is SET (TPM_RC_ATTRIBUTES).
    CLEAR (0): In a command, indicates that the session need not be
    exclusive at the start of the command. In a response, indicates that the
    session is not exclusive.
    """

    auditReset = 0x4
    """ SET (1): In a command, this setting indicates that the audit digest
    of the session should be initialized and the exclusive status of the
    session SET. This setting is only allowed if the audit attribute is SET
    (TPM_RC_ATTRIBUTES).
    CLEAR (0): In a command, indicates that the audit digest should not be
    initialized.
    This bit is always CLEAR in a response.
    """

    decrypt = 0x20
    """ SET (1): In a command, this setting indicates that the first
    parameter in the command is symmetrically encrypted using the parameter
    encryption scheme described in TPM 2.0 Part 1. The TPM will decrypt the
    parameter after performing any HMAC computations and before unmarshaling
    the parameter. In a response, the attribute is copied from the request
    but has no effect on the response.
    CLEAR (0): Session not used for encryption.
    For a password authorization, this attribute will be CLEAR in both the
    command and response.
    This attribute may be SET in a session that is not associated with a
    command handle. Such a session is provided for purposes of encrypting a
    parameter and not for authorization.
    This attribute may be SET in combination with any other session attributes.
    """

    encrypt = 0x40
    """ SET (1): In a command, this setting indicates that the TPM should
    use this session to encrypt the first parameter in the response. In a
    response, it indicates that the attribute was set in the command and
    that the TPM used the session to encrypt the first parameter in the
    response using the parameter encryption scheme described in TPM 2.0 Part
    1.
    CLEAR (0): Session not used for encryption.
    For a password authorization, this attribute will be CLEAR in both the
    command and response.
    This attribute may be SET in a session that is not associated with a
    command handle. Such a session is provided for purposes of encrypting a
    parameter and not for authorization.
    """

    audit = 0x80
    """ SET (1): In a command or response, this setting indicates that the
    session is for audit and that auditExclusive and auditReset have
    meaning. This session may also be used for authorization, encryption, or
    decryption. The encrypted and encrypt fields may be SET or CLEAR.
    CLEAR (0): Session is not used for audit.
    If SET in the command, then this attribute will be SET in the response.
    """
# bitfield TPMA_SESSION

class TPMA_LOCALITY(IntFlag): # UINT8
    """ In a TPMS_CREATION_DATA structure, this structure is used to
    indicate the locality of the command that created the object. No more
    than one of the locality attributes shall be set in the creation data.
    """

    LOC_ZERO = 0x1

    LOC_ONE = 0x2

    LOC_TWO = 0x4

    LOC_THREE = 0x8

    LOC_FOUR = 0x10

    Extended_BIT_MASK = 0xE0
    """ If any of these bits is set, an extended locality is indicated """

    Extended_BIT_OFFSET = 5

    Extended_BIT_LENGTH = 3
# bitfield TPMA_LOCALITY

class TPMA_PERMANENT(IntFlag): # UINT32
    """ The attributes in this structure are persistent and are not changed
    as a result of _TPM_Init or any TPM2_Startup(). Some of the attributes
    in this structure may change as the result of specific Protected
    Capabilities. This structure may be read using
    TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property =
    TPM_PT_PERMANENT).
    """

    ownerAuthSet = 0x1
    """ SET (1): TPM2_HierarchyChangeAuth() with ownerAuth has been executed
    since the last TPM2_Clear().
    CLEAR (0): ownerAuth has not been changed since TPM2_Clear().
    """

    endorsementAuthSet = 0x2
    """ SET (1): TPM2_HierarchyChangeAuth() with endorsementAuth has been
    executed since the last TPM2_Clear().
    CLEAR (0): endorsementAuth has not been changed since TPM2_Clear().
    """

    lockoutAuthSet = 0x4
    """ SET (1): TPM2_HierarchyChangeAuth() with lockoutAuth has been
    executed since the last TPM2_Clear().
    CLEAR (0): lockoutAuth has not been changed since TPM2_Clear().
    """

    disableClear = 0x100
    """ SET (1): TPM2_Clear() is disabled.
    CLEAR (0): TPM2_Clear() is enabled.
    NOTE See TPM2_ClearControl in TPM 2.0 Part 3 for details on changing
    this attribute.
    """

    inLockout = 0x200
    """ SET (1): The TPM is in lockout, when failedTries is equal to maxTries. """

    tpmGeneratedEPS = 0x400
    """ SET (1): The EPS was created by the TPM.
    CLEAR (0): The EPS was created outside of the TPM using a
    manufacturer-specific process.
    """
# bitfield TPMA_PERMANENT

class TPMA_STARTUP_CLEAR(IntFlag): # UINT32
    """ This structure may be read using TPM2_GetCapability(capability =
    TPM_CAP_TPM_PROPERTIES, property = TPM_PT_STARTUP_CLEAR).
    """

    phEnable = 0x1
    """ SET (1): The platform hierarchy is enabled and platformAuth or
    platformPolicy may be used for authorization.
    CLEAR (0): platformAuth and platformPolicy may not be used for
    authorizations, and objects in the platform hierarchy, including
    persistent objects, cannot be used.
    NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing
    this attribute.
    """

    shEnable = 0x2
    """ SET (1): The Storage hierarchy is enabled and ownerAuth or
    ownerPolicy may be used for authorization. NV indices defined using
    owner authorization are accessible.
    CLEAR (0): ownerAuth and ownerPolicy may not be used for authorizations,
    and objects in the Storage hierarchy, persistent objects, and NV indices
    defined using owner authorization cannot be used.
    NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing
    this attribute.
    """

    ehEnable = 0x4
    """ SET (1): The EPS hierarchy is enabled and Endorsement Authorization
    may be used to authorize commands.
    CLEAR (0): Endorsement Authorization may not be used for authorizations,
    and objects in the endorsement hierarchy, including persistent objects,
    cannot be used.
    NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing
    this attribute.
    """

    phEnableNV = 0x8
    """ SET (1): NV indices that have TPMA_NV_PLATFORMCREATE SET may be read
    or written. The platform can create define and undefine indices.
    CLEAR (0): NV indices that have TPMA_NV_PLATFORMCREATE SET may not be
    read or written (TPM_RC_HANDLE). The platform cannot define
    (TPM_RC_HIERARCHY) or undefined (TPM_RC_HANDLE) indices.
    NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing
    this attribute.
    NOTE
    read refers to these commands: TPM2_NV_Read, TPM2_NV_ReadPublic,
    TPM_NV_Certify, TPM2_PolicyNV
    write refers to these commands: TPM2_NV_Write, TPM2_NV_Increment,
    TPM2_NV_Extend, TPM2_NV_SetBits
    NOTE The TPM must query the index TPMA_NV_PLATFORMCREATE attribute to
    determine whether phEnableNV is applicable. Since the TPM will return
    TPM_RC_HANDLE if the index does not exist, it also returns this error
    code if the index is disabled. Otherwise, the TPM would leak the
    existence of an index even when disabled.
    """

    orderly = 0x80000000
    """ SET (1): The TPM received a TPM2_Shutdown() and a matching TPM2_Startup().
    CLEAR (0): TPM2_Startup(TPM_SU_CLEAR) was not preceded by a
    TPM2_Shutdown() of any type.
    NOTE A shutdown is orderly if the TPM receives a TPM2_Shutdown() of any
    type followed by a TPM2_Startup() of any type. However, the TPM will
    return an error if TPM2_Startup(TPM_SU_STATE) was not preceded by
    TPM2_Shutdown(TPM_SU_STATE).
    """
# bitfield TPMA_STARTUP_CLEAR

class TPMA_MEMORY(IntFlag): # UINT32
    """ This structure of this attribute is used to report the memory
    management method used by the TPM for transient objects and
    authorization sessions. This structure may be read using
    TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property =
    TPM_PT_MEMORY).
    """

    sharedRAM = 0x1
    """ SET (1): indicates that the RAM memory used for authorization
    session contexts is shared with the memory used for transient objects
    CLEAR (0): indicates that the memory used for authorization sessions is
    not shared with memory used for transient objects
    """

    sharedNV = 0x2
    """ SET (1): indicates that the NV memory used for persistent objects is
    shared with the NV memory used for NV Index values
    CLEAR (0): indicates that the persistent objects and NV Index values are
    allocated from separate sections of NV
    """

    objectCopiedToRam = 0x4
    """ SET (1): indicates that the TPM copies persistent objects to a
    transient-object slot in RAM when the persistent object is referenced in
    a command. The TRM is required to make sure that an object slot is available.
    CLEAR (0): indicates that the TPM does not use transient-object slots
    when persistent objects are referenced
    """
# bitfield TPMA_MEMORY

class TPMA_CC(Flag): # TPM_CC
    """ This structure defines the attributes of a command from a context
    management perspective. The fields of the structure indicate to the TPM
    Resource Manager (TRM) the number of resources required by a command and
    how the command affects the TPMs resources.
    """

    commandIndex_BIT_MASK = 0xFFFF
    """ Indicates the command being selected """

    commandIndex_BIT_OFFSET = 0

    commandIndex_BIT_LENGTH = 16

    nv = 0x400000
    """ SET (1): indicates that the command may write to NV
    CLEAR (0): indicates that the command does not write to NV
    """

    extensive = 0x800000
    """ SET (1): This command could flush any number of loaded contexts.
    CLEAR (0): no additional changes other than indicated by the flushed attribute
    """

    flushed = 0x1000000
    """ SET (1): The context associated with any transient handle in the
    command will be flushed when this command completes.
    CLEAR (0): No context is flushed as a side effect of this command.
    """

    cHandles_BIT_MASK = 0xE000000
    """ Indicates the number of the handles in the handle area for this command """

    cHandles_BIT_OFFSET = 25

    cHandles_BIT_LENGTH = 3

    rHandle = 0x10000000
    """ SET (1): indicates the presence of the handle area in the response """

    V = 0x20000000
    """ SET (1): indicates that the command is vendor-specific
    CLEAR (0): indicates that the command is defined in a version of this
    specification
    """

    Res_BIT_MASK = 0xC0000000
    """ Allocated for software; shall be zero """

    Res_BIT_OFFSET = 30

    Res_BIT_LENGTH = 2
# bitfield TPMA_CC

class TPMA_MODES(IntFlag): # UINT32
    """ This structure of this attribute is used to report that the TPM is
    designed for these modes. This structure may be read using
    TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property =
    TPM_PT_MODES).
    """

    FIPS_140_2 = 0x1
    """ SET (1): indicates that the TPM is designed to comply with all of
    the FIPS 140-2 requirements at Level 1 or higher.
    """
# bitfield TPMA_MODES

class TPMA_X509_KEY_USAGE(IntFlag): # UINT32
    """ These attributes are as specified in clause 4.2.1.3. of RFC 5280
    Internet X.509 Public Key Infrastructure Certificate and Certificate
    Revocation List (CRL) Profile. For TPM2_CertifyX509, when a caller
    provides a DER encoded Key Usage in partialCertificate, the TPM will
    validate that the key to be certified meets the requirements of Key Usage.
    """

    decipherOnly = 0x800000
    """ Attributes.Decrypt SET """

    encipherOnly = 0x1000000
    """ Attributes.Decrypt SET """

    cRLSign = 0x2000000
    """ Attributes.sign SET """

    keyCertSign = 0x4000000
    """ Attributes.sign SET """

    keyAgreement = 0x8000000
    """ Attributes.Decrypt SET """

    dataEncipherment = 0x10000000
    """ Attributes.Decrypt SET """

    keyEncipherment = 0x20000000
    """ Asymmetric key with decrypt and restricted SET key has the
    attributes of a parent key
    """

    nonrepudiation = 0x40000000
    """ FixedTPM SET in Subject Key (objectHandle) """

    contentCommitment = 0x40000000
    """ Alias to the nonrepudiation value. """

    digitalSignature = 0x80000000
    """ Sign SET in Subject Key (objectHandle) """
# bitfield TPMA_X509_KEY_USAGE

class TPMA_ACT(Flag): # UINT32
    """ This attribute is used to report the ACT state. This attribute may
    be read using TPM2_GetCapability(capability = TPM_CAP_ACT, property =
    TPM_RH_ACT_x where x is the ACT number (0-F)). The signaled value must
    be preserved across TPM Resume or if the TPM has not lost power. The
    signaled value may be preserved over a power cycle of a TPM.
    """

    signaled = 0x1
    """ SET (1): The ACT has signaled
    CLEAR (0): The ACT has not signaled
    """

    preserveSignaled = 0x2
    """ Preserves the state of signaled, depending on the power cycle """
# bitfield TPMA_ACT

class TPM_NV_INDEX(IntFlag): # UINT32
    """ A TPM_NV_INDEX is used to reference a defined location in NV memory.
    The format of the Index is changed from TPM 1.2 in order to include the
    Index in the reserved handle space. Handles in this range use the digest
    of the public area of the Index as the Name of the entity in
    authorization computations
    """

    index_BIT_MASK = 0xFFFFFF
    """ The Index of the NV location """

    index_BIT_OFFSET = 0

    index_BIT_LENGTH = 24

    RhNv_BIT_MASK = 0xFF000000
    """ Constant value of TPM_HT_NV_INDEX indicating the NV Index range """

    RhNv_BIT_OFFSET = 24

    RhNv_BIT_LENGTH = 8
# bitfield TPM_NV_INDEX

class TPMA_NV(IntFlag): # UINT32
    """ This structure allows the TPM to keep track of the data and
    permissions to manipulate an NV Index.
    """

    PPWRITE = 0x1
    """ SET (1): The Index data can be written if Platform Authorization is
    provided.
    CLEAR (0): Writing of the Index data cannot be authorized with Platform
    Authorization.
    """

    OWNERWRITE = 0x2
    """ SET (1): The Index data can be written if Owner Authorization is provided.
    CLEAR (0): Writing of the Index data cannot be authorized with Owner
    Authorization.
    """

    AUTHWRITE = 0x4
    """ SET (1): Authorizations to change the Index contents that require
    USER role may be provided with an HMAC session or password.
    CLEAR (0): Authorizations to change the Index contents that require USER
    role may not be provided with an HMAC session or password.
    """

    POLICYWRITE = 0x8
    """ SET (1): Authorizations to change the Index contents that require
    USER role may be provided with a policy session.
    CLEAR (0): Authorizations to change the Index contents that require USER
    role may not be provided with a policy session.
    NOTE TPM2_NV_ChangeAuth() always requires that authorization be provided
    in a policy session.
    """

    ORDINARY = 0x0
    """ Ordinary contains data that is opaque to the TPM that can only be
    modified using TPM2_NV_Write().
    """

    COUNTER = 0x10
    """ Counter contains an 8-octet value that is to be used as a counter
    and can only be modified with TPM2_NV_Increment()
    """

    BITS = 0x20
    """ Bit Field contains an 8-octet value to be used as a bit field and
    can only be modified with TPM2_NV_SetBits().
    """

    EXTEND = 0x40
    """ Extend contains a digest-sized value used like a PCR. The Index can
    only be modified using TPM2_NV_Extend(). The extend will use the nameAlg
    of the Index.
    """

    PIN_FAIL = 0x80
    """ PIN Fail - contains pinCount that increments on a PIN authorization
    failure and a pinLimit
    """

    PIN_PASS = 0x90
    """ PIN Pass - contains pinCount that increments on a PIN authorization
    success and a pinLimit
    """

    TpmNt_BIT_MASK = 0xF0
    """ The type of the index.
    NOTE A TPM is not required to support all TPM_NT values
    """

    TpmNt_BIT_OFFSET = 4

    TpmNt_BIT_LENGTH = 4

    POLICY_DELETE = 0x400
    """ SET (1): Index may not be deleted unless the authPolicy is satisfied
    using TPM2_NV_UndefineSpaceSpecial().
    CLEAR (0): Index may be deleted with proper platform or owner
    authorization using TPM2_NV_UndefineSpace().
    NOTE An Index with this attribute and a policy that cannot be satisfied
    (e.g., an Empty Policy) cannot be deleted.
    """

    WRITELOCKED = 0x800
    """ SET (1): Index cannot be written.
    CLEAR (0): Index can be written.
    """

    WRITEALL = 0x1000
    """ SET (1): A partial write of the Index data is not allowed. The write
    size shall match the defined space size.
    CLEAR (0): Partial writes are allowed. This setting is required if the
    .dataSize of the Index is larger than NV_MAX_BUFFER_SIZE for the
    implementation.
    """

    WRITEDEFINE = 0x2000
    """ SET (1): TPM2_NV_WriteLock() may be used to prevent further writes
    to this location.
    CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if
    TPMA_NV_WRITE_STCLEAR is also CLEAR.
    """

    WRITE_STCLEAR = 0x4000
    """ SET (1): TPM2_NV_WriteLock() may be used to prevent further writes
    to this location until the next TPM Reset or TPM Restart.
    CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if
    TPMA_NV_WRITEDEFINE is also CLEAR.
    """

    GLOBALLOCK = 0x8000
    """ SET (1): If TPM2_NV_GlobalWriteLock() is successful,
    TPMA_NV_WRITELOCKED is set.
    CLEAR (0): TPM2_NV_GlobalWriteLock() has no effect on the writing of the
    data at this Index.
    """

    PPREAD = 0x10000
    """ SET (1): The Index data can be read if Platform Authorization is provided.
    CLEAR (0): Reading of the Index data cannot be authorized with Platform
    Authorization.
    """

    OWNERREAD = 0x20000
    """ SET (1): The Index data can be read if Owner Authorization is provided.
    CLEAR (0): Reading of the Index data cannot be authorized with Owner
    Authorization.
    """

    AUTHREAD = 0x40000
    """ SET (1): The Index data may be read if the authValue is provided.
    CLEAR (0): Reading of the Index data cannot be authorized with the Index
    authValue.
    """

    POLICYREAD = 0x80000
    """ SET (1): The Index data may be read if the authPolicy is satisfied.
    CLEAR (0): Reading of the Index data cannot be authorized with the Index
    authPolicy.
    """

    NO_DA = 0x2000000
    """ SET (1): Authorization failures of the Index do not affect the DA
    logic and authorization of the Index is not blocked when the TPM is in
    Lockout mode.
    CLEAR (0): Authorization failures of the Index will increment the
    authorization failure counter and authorizations of this Index are not
    allowed when the TPM is in Lockout mode.
    """

    ORDERLY = 0x4000000
    """ SET (1): NV Index state is only required to be saved when the TPM
    performs an orderly shutdown (TPM2_Shutdown()).
    CLEAR (0): NV Index state is required to be persistent after the command
    to update the Index completes successfully (that is, the NV update is
    synchronous with the update command).
    """

    CLEAR_STCLEAR = 0x8000000
    """ SET (1): TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM
    Restart.
    CLEAR (0): TPMA_NV_WRITTEN is not changed by TPM Restart.
    NOTE This attribute may only be SET if TPM_NT is not TPM_NT_COUNTER.
    """

    READLOCKED = 0x10000000
    """ SET (1): Reads of the Index are blocked until the next TPM Reset or
    TPM Restart.
    CLEAR (0): Reads of the Index are allowed if proper authorization is provided.
    """

    WRITTEN = 0x20000000
    """ SET (1): Index has been written.
    CLEAR (0): Index has not been written.
    """

    PLATFORMCREATE = 0x40000000
    """ SET (1): This Index may be undefined with Platform Authorization but
    not with Owner Authorization.
    CLEAR (0): This Index may be undefined using Owner Authorization but not
    with Platform Authorization.
    The TPM will validate that this attribute is SET when the Index is
    defined using Platform Authorization and will validate that this
    attribute is CLEAR when the Index is defined using Owner Authorization.
    """

    READ_STCLEAR = 0x80000000
    """ SET (1): TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED
    for this Index.
    CLEAR (0): TPM2_NV_ReadLock() has no effect on this Index.
    """
# bitfield TPMA_NV
