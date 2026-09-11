#include <logicalaccess/plugins/readers/iso7816/commands/duoxiso7816commands.hpp>

#include <logicalaccess/plugins/cards/desfire/desfirechip.hpp>
#include <logicalaccess/plugins/cards/desfire/desfireev2crypto.hpp>

#include <logicalaccess/plugins/crypto/lla_random.hpp>
#include <logicalaccess/plugins/crypto/aes_helper.hpp>

// Remove later
#include <iomanip>
#include <sstream>
#include <logicalaccess/plugins/crypto/x509V3Certificate.hpp>

namespace logicalaccess
{

namespace
{

// -------------------------------------------------------------------------
// Remove later
// -------------------------------------------------------------------------
void printInfo(const std::string &message)
{
    std::cout << "[INFO] " << message << '\n';
}

static std::string hexDump(const ByteVector &data)
{
    std::ostringstream oss;
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        if (i != 0)
            oss << ' ';
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

void verifySignatureWithCertificate(const ByteVector &certificateDER, const ByteVector &message,
                                    const ECDSASignature &signature)
{
    logicalaccess::X509V3Certificate certificate(certificateDER);

    EVP_PKEY *certificateKey = certificate.getEVPPublicKey();

    if (certificateKey == nullptr)
        throw std::runtime_error("Cert.A does not contain a public key.");

    if (EVP_PKEY_base_id(certificateKey) != EVP_PKEY_EC)
    {
        EVP_PKEY_free(certificateKey);
        throw std::runtime_error("Cert.A public key is not an EC key.");
    }

    // Convert DUOX r/s representation back to the DER signature representation expected by OpenSSL
    const ByteVector derSignature = encodeECDSASignatureDER(signature);

    if (derSignature.empty())
    {
        EVP_PKEY_free(certificateKey);
        throw std::runtime_error("Unable to encode DUOX ECDSA signature.");
    }

    // Verify ECDSA-SHA256(message, Cert.A public key)
    // signECDSA() hashes the message internally so verification must use SHA-256 as well
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
    {
        EVP_PKEY_free(certificateKey);
        throw std::runtime_error("Unable to allocate EVP_MD_CTX.");
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, certificateKey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(certificateKey);
        throw std::runtime_error("EVP_DigestVerifyInit failed for Cert.A public key.");
    }

    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(certificateKey);
        throw std::runtime_error("EVP_DigestVerifyUpdate failed.");
    }

    const int result = EVP_DigestVerifyFinal(ctx, derSignature.data(), derSignature.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(certificateKey);

    if (result != 1)
        throw std::runtime_error("DUOX Sig.A verification failed using the public key contained in Cert.A.");
    std::cout << "[INFO] DUOX Sig.A verified with Cert.A public key." << std::endl;
}

static void debugBytes(const std::string &label, const ByteVector &data)
{
    printInfo(label + " [" + std::to_string(data.size()) + " bytes]: " + hexDump(data));
}

// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------

constexpr std::uint8_t DUOX_INS_GET_KEY_SETTINGS   = 0x45;
constexpr std::uint8_t DUOX_INS_MANAGE_KEY_PAIR    = 0x46;
constexpr std::uint8_t DUOX_INS_EXPORT_KEY         = 0x47;
constexpr std::uint8_t DUOX_INS_MANAGE_CA_ROOT_KEY = 0x48;
constexpr std::uint8_t DUOX_INS_CHANGE_KEY         = 0xC4;
constexpr std::uint8_t DUOX_INS_CHANGE_KEY_EV2     = 0xC6;

constexpr std::uint8_t DFEV2_INS_AUTHENTICATE_EV2_NON_FIRST = 0x77;

constexpr std::uint8_t DUOX_PICC_LEVEL_AID  = 0x00;
constexpr std::uint8_t DUOX_MAX_PICC_KEY_NO = 0x01;
constexpr std::uint8_t DUOX_MAX_KEY_NO      = 0x04;

constexpr std::size_t DUOX_ECC_PRIVATE_KEY_SIZE = 32;
/*
 * CA public key :
 *   0x04 || X || Y
 * P-256 uncompressed public keys are exactly 65 bytes
 */
constexpr std::size_t DUOX_ECC_PUBLIC_KEY_SIZE = 65;

// WriteAccess:
//   bits 0-3 : WriteAR
//   bits 4-5 : communication mode
//   bits 6-7 : RFU
constexpr std::uint8_t ACCESS_COM_MODE_MASK = 0x30;
constexpr std::uint8_t ACCESS_RFU_MASK      = 0xC0;

// AccessRights bits 14 and 15 are RFU
constexpr std::uint16_t ACCESS_RIGHTS_VALID_MASK = 0x3FFF;

/*
 * CRLFile :
 *
 *   bit 7    : CRL enabled
 *   bits 5-6 : RFU
 *   bits 0-4 : CRL File number when enabled, otherwise zero
 */
constexpr std::uint8_t CRL_FILE_ENABLED_MASK = 0x80;
constexpr std::uint8_t CRL_FILE_NUMBER_MASK  = 0x1F;
constexpr std::uint8_t CRL_FILE_RFU_MASK     = 0x60;
constexpr std::uint32_t AID_3_BYTE_MASK      = 0x00FFFFFF;

constexpr std::uint16_t KEY_POLICY_VALID_MASK =
    static_cast<std::uint16_t>((1u << 4) | // CryptoRequest
                               (1u << 5) | // SecureDynamicMessaging
                               (1u << 6) | // TransactionSignature
                               (1u << 7) | // MutualAuthentication
                               (1u << 8) | // UnilateralAuthentication
                               (1u << 15)  // FreezeKeyUsageCounter
    );

// Append a little-endian 16-bit value
void appendUShortLE(ByteVector &buffer, std::uint16_t value)
{
    buffer.push_back(static_cast<std::uint8_t>(value & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

// Append a little-endian 32-bit value
void appendUIntLE(ByteVector &buffer, std::uint32_t value)
{
    buffer.push_back(static_cast<std::uint8_t>(value & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

std::string byteToHex(std::uint8_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << static_cast<unsigned int>(value);
    return stream.str();
}

// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
struct DUOXExpectedStatus
{
    std::uint8_t sw1;
    std::uint8_t sw2;
};

constexpr DUOXExpectedStatus DUOX_SUCCESS = {0x91, 0x00};

// For now any non-zero status on 0x9100 is considered failure
void checkSuccess(const ISO7816Response &response, DUOXExpectedStatus expected, const char *caller)
{
    EXCEPTION_ASSERT_WITH_LOG(response.getSW1() == expected.sw1 && response.getSW2() == expected.sw2,
        LibLogicalAccessException,
        std::string(caller) + " failed with status word " +
            byteToHex(response.getSW1()) + " " + byteToHex(response.getSW2()) +
            ", expected " + byteToHex(expected.sw1) + " " + byteToHex(expected.sw2) + ".");
}

// Might be better than checkSuccess if only want to check SW2 like DUOX commands do. But at transmit,
// we get transmission response (SW1=0x91 or another code in very rare cases of error) and DUOX response (SW1)
void checkSW2(const ISO7816Response &response, std::uint8_t expectedSW2, const char *caller)
{
    EXCEPTION_ASSERT_WITH_LOG(response.getSW2() == expectedSW2,
        LibLogicalAccessException,
        std::string(caller) + " failed with SW2 " + byteToHex(response.getSW2()) + ", expected " +
        byteToHex(expectedSW2) + ".");
}
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------

} // namespace

// DUOXCommands and DESFireEV3ISO7816Commands both derive from DESFireEV3Commands
// The inheritance is intentionally non-virtual for now
// The explicit forwarding below selects the ISO7816 implementation for all
// DESFire commands and resolves the resulting diamond/ambiguity

DUOXISO7816Commands::DUOXISO7816Commands()
    : DESFireEV3ISO7816Commands(CMD_DUOXISO7816)
{
    // DUOXCommands provides the DUOX command abstraction while
    // DESFireEV3ISO7816Commands provides the ISO7816 implementation
}

// ------------------
// Common / transport
// ------------------
std::shared_ptr<Chip> DUOXISO7816Commands::getChip() const
{
    return DESFireEV3ISO7816Commands::getChip();
}

std::shared_ptr<ReaderCardAdapter> DUOXISO7816Commands::getReaderCardAdapter() const
{
    return DESFireEV3ISO7816Commands::getReaderCardAdapter();
}

ISO7816Response DUOXISO7816Commands::transmitDUOX(std::uint8_t cmd, const ByteVector &params, const ByteVector &data,
    DUOXCommunicationMode commMode)
{
    switch (commMode)
    {
    case DUOXCommunicationMode::Plain:
    {
        ByteVector command = params;
        command.insert(command.end(), data.begin(), data.end());
        return transmit_plain(cmd, command);
    }
    case DUOXCommunicationMode::MAC:
    {
        ByteVector command = params;
        command.insert(command.end(), data.begin(), data.end());
        return transmit(cmd, command);
    }
    case DUOXCommunicationMode::Full:
    {
        return transmit_full(cmd, data, params);
    }

    default:
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException, "Invalid DUOX communication mode.");
    }
}

// ------------------
// DUOX
// ------------------
ByteVector DUOXISO7816Commands::manageKeyPair(std::uint8_t keyNo, DUOXManageKeyPairOption option,
                                              CurveID curveId, std::uint16_t keyPolicy,
                                              std::uint8_t writeAccess, std::uint32_t kucLimit,
                                              const ByteVector &privateKey, DUOXCommunicationMode commMode)
{
    const auto chip = getDESFireChip();

    EXCEPTION_ASSERT_WITH_LOG(chip != nullptr,
        LibLogicalAccessException, "DUOX ManageKeyPair requires an initialized DESFire chip.");

    const auto crypto = chip->getCrypto();

    EXCEPTION_ASSERT_WITH_LOG(crypto != nullptr,
        LibLogicalAccessException, "DUOX ManageKeyPair requires an initialized DESFire crypto context.");

    const bool piccLevel = crypto->d_currentAid == DUOX_PICC_LEVEL_AID;

    const std::uint8_t maximumKeyNo = piccLevel ? DUOX_MAX_PICC_KEY_NO : DUOX_MAX_KEY_NO;

    EXCEPTION_ASSERT_WITH_LOG(keyNo <= maximumKeyNo,
        LibLogicalAccessException,
        "Invalid DUOX ECC private key number " + byteToHex(keyNo) +
            ". Maximum allowed key number is " + byteToHex(maximumKeyNo) +
            (piccLevel ? " at PICC level." : " at application level."));

    switch (option)
    {
    case DUOXManageKeyPairOption::GenerateKeyPair:
        EXCEPTION_ASSERT_WITH_LOG(privateKey.empty(),
            LibLogicalAccessException, "A private key must not be supplied for DUOX ManageKeyPair key-pair generation.");
        break;

    case DUOXManageKeyPairOption::ImportPrivateKey:
        EXCEPTION_ASSERT_WITH_LOG(privateKey.size() == DUOX_ECC_PRIVATE_KEY_SIZE,
            LibLogicalAccessException, "DUOX ManageKeyPair private key import requires exactly 32 bytes.");
        break;

    case DUOXManageKeyPairOption::UpdateMetadata:
        EXCEPTION_ASSERT_WITH_LOG(privateKey.empty(),
            LibLogicalAccessException, "A private key must not be supplied for DUOX ManageKeyPair metadata update.");
        break;

    default:
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException, "Invalid DUOX ManageKeyPair option.");
    }

    switch (curveId)
    {
    case CurveID::NIST_P256:
    case CurveID::BRAINPOOL_P256R1: break;
    default:
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
            "Unsupported DUOX CurveID " + byteToHex(static_cast<std::uint8_t>(curveId)) + ".");
    }

    EXCEPTION_ASSERT_WITH_LOG((keyPolicy & ~KEY_POLICY_VALID_MASK) == 0,
        LibLogicalAccessException, "Invalid DUOX KeyPolicy : reserved bits are set.");

    EXCEPTION_ASSERT_WITH_LOG((writeAccess & ACCESS_RFU_MASK) == 0,
        LibLogicalAccessException, "Invalid DUOX WriteAccess : reserved bits 6 and 7 must be zero.");

    const auto writeAccessCommMode = static_cast<DUOXCommunicationMode>((writeAccess & ACCESS_COM_MODE_MASK) >> 4);

    EXCEPTION_ASSERT_WITH_LOG(writeAccessCommMode == DUOXCommunicationMode::Plain ||
                                  writeAccessCommMode == DUOXCommunicationMode::MAC ||
                                  writeAccessCommMode == DUOXCommunicationMode::Full,
        LibLogicalAccessException, "Invalid DUOX WriteAccess communication mode : 0b10 is reserved.");
    
    // KeyNo (1) + Option (1) + CurveID (1) + KeyPolicy (2) + WriteAccess (1) + KUCLimit (4)
    constexpr std::size_t HEADER_PARAMETERS_SIZE = 10;

    const std::size_t DATA_PARAMETERS_SIZE =
        (option == DUOXManageKeyPairOption::ImportPrivateKey ? DUOX_ECC_PRIVATE_KEY_SIZE : 0);

    ByteVector params;
    params.reserve(HEADER_PARAMETERS_SIZE);
    params.push_back(keyNo);
    params.push_back(static_cast<std::uint8_t>(option));
    params.push_back(static_cast<std::uint8_t>(curveId));
    appendUShortLE(params, keyPolicy);
    params.push_back(writeAccess);
    appendUIntLE(params, kucLimit);

    ByteVector command;
    if (option == DUOXManageKeyPairOption::ImportPrivateKey)
    {
        command.reserve(DATA_PARAMETERS_SIZE);
        command.insert(command.end(), privateKey.begin(), privateKey.end());
    }
    
    const auto response = transmitDUOX(DUOX_INS_MANAGE_KEY_PAIR, params, command, commMode);

    std::cout << "\n========== DUOX ManageKeyPair RESPONSE ==========\n"
              << "SW1 : " << byteToHex(response.getSW1()) << "\n"
              << "SW2 : " << byteToHex(response.getSW2()) << "\n"
              << std::dec
              << "Data size : " << response.getData().size() << " bytes\n"
              << "Hex string size : " << logicalaccess::BufferHelper::getHex(response.getData()).size() << " characters\n"
              << "Data : " << logicalaccess::BufferHelper::getHex(response.getData()) << "\n"
              << "\n"
              << "=================================================\n";

    checkSuccess(response, DUOX_SUCCESS, __func__);

    switch (option)
    {
    case DUOXManageKeyPairOption::GenerateKeyPair:
    {
        const ByteVector responseData = response.getData();
        EXCEPTION_ASSERT_WITH_LOG(!responseData.empty(), LibLogicalAccessException,
                                  "DUOX ManageKeyPair key generation succeeded but "
                                  "the card returned an empty public key.");
        return responseData;
    }

    case DUOXManageKeyPairOption::ImportPrivateKey:
    case DUOXManageKeyPairOption::UpdateMetadata:
        EXCEPTION_ASSERT_WITH_LOG(response.getData().empty(), LibLogicalAccessException,
                                  "DUOX ManageKeyPair returned unexpected response data "
                                  "for an operation that does not return a public key.");
        return {};

    default:
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException, "Invalid DUOX ManageKeyPair option.");
    }
}

void DUOXISO7816Commands::manageCARootKey(
    std::uint8_t keyNo, CurveID curveId, std::uint16_t accessRights,
    std::uint8_t writeAccess, std::uint8_t readAccess, std::uint8_t crlFile,
    std::uint32_t crlFileAid, const ByteVector &publicKey, const ByteVector &issuer,
    DUOXCommunicationMode commMode)
{
    const auto chip = getDESFireChip();

    EXCEPTION_ASSERT_WITH_LOG(chip != nullptr,
        LibLogicalAccessException, "DUOX ManageCARootKey requires an initialized DESFire chip.");

    const auto crypto = chip->getCrypto();

    EXCEPTION_ASSERT_WITH_LOG(crypto != nullptr,
        LibLogicalAccessException, "DUOX ManageCARootKey requires an initialized DESFire crypto context.");

    const bool piccLevel = crypto->d_currentAid == DUOX_PICC_LEVEL_AID;

    const std::uint8_t maximumKeyNo = piccLevel ? DUOX_MAX_PICC_KEY_NO : DUOX_MAX_KEY_NO;

    EXCEPTION_ASSERT_WITH_LOG((keyNo & 0xF8) == 0,
        LibLogicalAccessException, "Invalid DUOX CA Root Key number : reserved bits 3 to 7 must be zero.");

    EXCEPTION_ASSERT_WITH_LOG(keyNo <= maximumKeyNo,
        LibLogicalAccessException,
        "Invalid DUOX CA Root Key number " + byteToHex(keyNo) +
            ". Maximum allowed key number is " + byteToHex(maximumKeyNo) +
            (piccLevel ? " at PICC level." : " at application level."));

    // CurveID currently supports only the two curves defined by DUOX.
    switch (curveId)
    {
    case CurveID::NIST_P256:
    case CurveID::BRAINPOOL_P256R1: break;

    default:
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
            "Unsupported DUOX CurveID " + byteToHex(static_cast<std::uint8_t>(curveId)) + ".");
    }

    EXCEPTION_ASSERT_WITH_LOG((accessRights & ~ACCESS_RIGHTS_VALID_MASK) == 0,
        LibLogicalAccessException, "Invalid DUOX CA Root Key AccessRights : reserved bits 14 and 15 must be zero.");

    EXCEPTION_ASSERT_WITH_LOG((writeAccess & ACCESS_RFU_MASK) == 0,
        LibLogicalAccessException, "Invalid DUOX WriteAccess : reserved bits 6 and 7 must be zero.");

    EXCEPTION_ASSERT_WITH_LOG((readAccess & ACCESS_RFU_MASK) == 0,
        LibLogicalAccessException, "Invalid DUOX ReadAccess : reserved bits 6 and 7 must be zero.");

    const auto writeAccessCommMode = static_cast<DUOXCommunicationMode>((writeAccess & ACCESS_COM_MODE_MASK) >> 4);

    EXCEPTION_ASSERT_WITH_LOG(
        writeAccessCommMode == DUOXCommunicationMode::Plain ||
            writeAccessCommMode == DUOXCommunicationMode::MAC ||
            writeAccessCommMode == DUOXCommunicationMode::Full,
        LibLogicalAccessException,
        "Invalid DUOX WriteAccess communication mode : 0b10 is reserved.");

    const auto readAccessCommMode =
        static_cast<DUOXCommunicationMode>((readAccess & ACCESS_COM_MODE_MASK) >> 4);

    EXCEPTION_ASSERT_WITH_LOG(
        readAccessCommMode == DUOXCommunicationMode::Plain ||
            readAccessCommMode == DUOXCommunicationMode::MAC ||
            readAccessCommMode == DUOXCommunicationMode::Full,
        LibLogicalAccessException,
        "Invalid DUOX ReadAccess communication mode : 0b10 is reserved.");

    EXCEPTION_ASSERT_WITH_LOG((crlFile & CRL_FILE_RFU_MASK) == 0,
        LibLogicalAccessException, "Invalid DUOX CRLFile : reserved bits 5 and 6 must be zero.");

    const bool crlEnabled = (crlFile & CRL_FILE_ENABLED_MASK) != 0;

    if (!crlEnabled)
    {
        EXCEPTION_ASSERT_WITH_LOG(crlFile == 0x00,
            LibLogicalAccessException,
            "Invalid DUOX CRLFile : file number must be zero when certificate revocation is disabled.");

        EXCEPTION_ASSERT_WITH_LOG(crlFileAid == 0x000000,
            LibLogicalAccessException,
            "Invalid DUOX CRLFileAID : AID must be 0x000000 when certificate revocation is disabled.");
    }
    else
    {
        /*
         * CRLFileAID is represented by exactly three bytes on the wire.
         * Therefore the largest representable AID is 0x00FFFFFF.
         */
        EXCEPTION_ASSERT_WITH_LOG(crlFileAid <= AID_3_BYTE_MASK,
            LibLogicalAccessException, "Invalid DUOX CRLFileAID : only 3 bytes are supported.");
    }


    EXCEPTION_ASSERT_WITH_LOG(publicKey.size() == DUOX_ECC_PUBLIC_KEY_SIZE, LibLogicalAccessException,
        "DUOX CA Root Key requires exactly 65 bytes for an uncompressed ECC public key (0x04 || X || Y).");

    EXCEPTION_ASSERT_WITH_LOG(publicKey[0] == 0x04, LibLogicalAccessException,
        "Invalid DUOX CA Root Key public key : uncompressed ECC public keys must start with 0x04.");

    /*
     * IssuerLen is one byte on the wire, therefore Issuer is limited to
     * 255 bytes. An empty issuer means that no trusted-issuer check is
     * requested and results in IssuerLen == 0
     */
    EXCEPTION_ASSERT_WITH_LOG(
        issuer.size() <= 0xFF, LibLogicalAccessException,
        "DUOX CA Root Key issuer name is too long : maximum length is 255 bytes.");

    const auto issuerLen = static_cast<std::uint8_t>(issuer.size());

    /*
     * Header parameters:
     *
     *   KeyNo         1
     *   CurveID       1
     *   AccessRights  2
     *   WriteAccess   1
     *   ReadAccess    1
     *   CRLFile       1
     *   CRLFileAID    3
     *
     * Total = 10 bytes.
     */
    constexpr std::size_t HEADER_PARAMETERS_SIZE = 10;

    /*
     * Data parameters:
     *
     *   PublicKey    65
     *   IssuerLen     1
     *   Issuer        N
     */
    constexpr std::size_t PUBLIC_KEY_SIZE = DUOX_ECC_PUBLIC_KEY_SIZE;

    const std::size_t DATA_PARAMETERS_SIZE = PUBLIC_KEY_SIZE + 1 + issuer.size();

    ByteVector params;
    params.reserve(HEADER_PARAMETERS_SIZE);

    params.push_back(keyNo);
    params.push_back(static_cast<std::uint8_t>(curveId));
    appendUShortLE(params, accessRights);
    params.push_back(writeAccess);
    params.push_back(readAccess);
    params.push_back(crlFile);

    // CRLFileAID is exactly 3 bytes, LSB first.
    params.push_back(static_cast<std::uint8_t>(crlFileAid & 0xFF));
    params.push_back(static_cast<std::uint8_t>((crlFileAid >> 8) & 0xFF));
    params.push_back(static_cast<std::uint8_t>((crlFileAid >> 16) & 0xFF));

    EXCEPTION_ASSERT_WITH_LOG(params.size() == HEADER_PARAMETERS_SIZE,
        LibLogicalAccessException, "Internal DUOX ManageCARootKey error : invalid header parameter size.");

    ByteVector command;
    command.reserve(DATA_PARAMETERS_SIZE);
    command.insert(command.end(), publicKey.begin(), publicKey.end());
    command.push_back(issuerLen);
    if (!issuer.empty())
        command.insert(command.end(), issuer.begin(), issuer.end());

    EXCEPTION_ASSERT_WITH_LOG(command.size() == DATA_PARAMETERS_SIZE,
        LibLogicalAccessException, "Internal DUOX ManageCARootKey error : invalid command data parameter size.");

    const auto response = transmitDUOX(DUOX_INS_MANAGE_CA_ROOT_KEY, params, command, commMode);

    std::cout << "\n========== DUOX ManageCARootKey RESPONSE ==========\n"
              << "SW1 : " << byteToHex(response.getSW1()) << "\n"
              << "SW2 : " << byteToHex(response.getSW2()) << "\n"
              << std::dec << "Data size : " << response.getData().size() << " bytes\n"
              << "Hex string size : "
              << logicalaccess::BufferHelper::getHex(response.getData()).size()
              << " characters\n"
              << "Data : " << logicalaccess::BufferHelper::getHex(response.getData())
              << "\n"
              << "\n"
              << "=================================================\n";

    checkSuccess(response, DUOX_SUCCESS, __func__);

    EXCEPTION_ASSERT_WITH_LOG(response.getData().empty(),
        LibLogicalAccessException, "DUOX ManageCARootKey returned unexpected response data.");

    return;
}

ByteVector DUOXISO7816Commands::exportKey(std::uint8_t keyNo, DUOXCommunicationMode commMode)
{
    const auto chip = getDESFireChip();

    EXCEPTION_ASSERT_WITH_LOG(chip != nullptr,
        LibLogicalAccessException, "DUOX ExportKey requires an initialized DESFire chip.");

    const auto crypto = chip->getCrypto();

    EXCEPTION_ASSERT_WITH_LOG(crypto != nullptr,
        LibLogicalAccessException, "DUOX ExportKey requires an initialized DESFire crypto context.");

    const bool piccLevel = crypto->d_currentAid == DUOX_PICC_LEVEL_AID;

    const std::uint8_t maximumKeyNo = piccLevel ? DUOX_MAX_PICC_KEY_NO : DUOX_MAX_KEY_NO;

    EXCEPTION_ASSERT_WITH_LOG((keyNo & 0xF8) == 0,
        LibLogicalAccessException, "Invalid DUOX ExportKey number : reserved bits 3 to 7 must be zero.");

    EXCEPTION_ASSERT_WITH_LOG(keyNo <= maximumKeyNo,
        LibLogicalAccessException,
        "Invalid DUOX ExportKey number " + byteToHex(keyNo) + ". Maximum allowed key number is " + byteToHex(maximumKeyNo) +
            (piccLevel ? " at PICC level." : " at application level."));

    // Option = 0x01 (KeyID.CARootKey)
    constexpr std::uint8_t DUOX_EXPORT_KEY_OPTION_CA_ROOT_KEY = 0x01;

    ByteVector params;
    params.reserve(2);

    params.push_back(DUOX_EXPORT_KEY_OPTION_CA_ROOT_KEY);
    params.push_back(keyNo);

    constexpr std::size_t EXPORT_KEY_PARAMETERS_SIZE = 2;

    EXCEPTION_ASSERT_WITH_LOG(params.size() == EXPORT_KEY_PARAMETERS_SIZE,
        LibLogicalAccessException, "Internal DUOX ExportKey error : invalid command parameter size.");

    const auto response = transmitDUOX(DUOX_INS_EXPORT_KEY, params, {}, commMode);

    checkSuccess(response, DUOX_SUCCESS, __func__);

    const auto &publicKey = response.getData();
    std::cout << "\n========== DUOX ExportKey RESPONSE ==========\n"
              << "SW1       : " << byteToHex(response.getSW1()) << "\n"
              << "SW2       : " << byteToHex(response.getSW2()) << "\n"
              << "Data size : " << response.getData().size() << "\n"
              << "Data      : " << logicalaccess::BufferHelper::getHex(response.getData())
              << "\n"
              << "=============================================\n";

    EXCEPTION_ASSERT_WITH_LOG(publicKey.size() == DUOX_ECC_PUBLIC_KEY_SIZE,
        LibLogicalAccessException, "DUOX ExportKey returned an invalid public key size : expected 65 bytes, received " +
            std::to_string(publicKey.size()) + " bytes.");

    EXCEPTION_ASSERT_WITH_LOG(publicKey[0] == 0x04,
        LibLogicalAccessException,
        "DUOX ExportKey returned an invalid public key : uncompressed ECC public keys must start with 0x04.");

    return publicKey;
}

void DUOXISO7816Commands::authenticateEV2NonFirst(uint8_t keyno, std::shared_ptr<DESFireKey> currentKey)
{
    auto crypto = std::dynamic_pointer_cast<DESFireEV2Crypto>(getDESFireChip()->getCrypto());

    EXCEPTION_ASSERT_WITH_LOG(crypto != nullptr,
        LibLogicalAccessException, "DESFireEV2 crypto is required for AuthenticateEV2NonFirst.");

    EXCEPTION_ASSERT_WITH_LOG(crypto->d_auth_method == CryptoMethod::CM_EV2,
        LibLogicalAccessException, "AuthenticateEV2NonFirst requires an active EV2 authentication.");

    if (!currentKey)
        currentKey = crypto->getKey(0, keyno);

    EXCEPTION_ASSERT_WITH_LOG(currentKey != nullptr && currentKey->getKeyType() == DESFireKeyType::DF_KEY_AES,
        LibLogicalAccessException, "Invalid key type : expected DF_KEY_AES.");

    auto key = std::make_shared<DESFireKey>(*currentKey);

    ByteVector keydiv;
    const ByteVector diversify = getKeyInformations(key, keyno);
    crypto->getKey(key, diversify, keydiv);

    EXCEPTION_ASSERT_WITH_LOG(keydiv.size() == 16 || keydiv.size() == 32,
        LibLogicalAccessException, "Invalid AES authentication key size.");

    const ByteVector iv(16, 0x00);
    const ByteVector command = {keyno};

    auto response = transmit_plain(DFEV2_INS_AUTHENTICATE_EV2_NON_FIRST, command);
    
    // TODO Will lose "AuthenticateEV2NonFirst Part 1 failed : expected Additional Frame." if doing checkSuccess
    // constexpr DUOXExpectedStatus EXPECTED_ADDITIONAL_FRAME = {0x91, DF_INS_ADDITIONAL_FRAME};
    // checkSuccess(response, EXPECTED_ADDITIONAL_FRAME, __func__);
    // TODO later :
    /* constexpr std::uint8_t EXPECTED_SW1 = 0x91;
    constexpr std::uint8_t EXPECTED_SW2 = DF_INS_ADDITIONAL_FRAME;

    EXCEPTION_ASSERT_WITH_LOG(
        response.getSW1() == EXPECTED_SW1 && response.getSW2() == EXPECTED_SW2,
        LibLogicalAccessException,
        "AuthenticateEV2NonFirst Part 1 failed: expected 9100/91AF response.");*/

    EXCEPTION_ASSERT_WITH_LOG(response.getSW2() == DF_INS_ADDITIONAL_FRAME,
        LibLogicalAccessException, "AuthenticateEV2NonFirst Part 1 failed : expected Additional Frame.");

    EXCEPTION_ASSERT_WITH_LOG(response.getData().size() == 16,
        LibLogicalAccessException, "AuthenticateEV2NonFirst Part 1 returned an invalid RndB length.");

    const ByteVector rndB = AESHelper::AESDecrypt(response.getData(), keydiv, iv);

    EXCEPTION_ASSERT_WITH_LOG(rndB.size() == 16,
        LibLogicalAccessException, "AuthenticateEV2NonFirst returned an invalid RndB.");

    // Generate PCD challenge
    const ByteVector rndA = RandomHelper::bytes(16);

    // RndB' = RndB rotated left by one byte
    ByteVector rndBPrime = rndB;
    std::rotate(rndBPrime.begin(), rndBPrime.begin() + 1, rndBPrime.end());

    // Part 2 data : RndA || RndB'
    ByteVector challenge;
    challenge.reserve(32);
    challenge.insert(challenge.end(), rndA.begin(), rndA.end());
    challenge.insert(challenge.end(), rndBPrime.begin(), rndBPrime.end());

    const ByteVector encryptedChallenge = AESHelper::AESEncrypt(challenge, keydiv, iv);

    EXCEPTION_ASSERT_WITH_LOG(encryptedChallenge.size() == 32,
        LibLogicalAccessException, "AuthenticateEV2NonFirst challenge has an invalid length.");

    // AF E(Kx, RndA || RndB') <- E(Kx, RndA'), SW = 9100
    response = transmit_plain(DF_INS_ADDITIONAL_FRAME, encryptedChallenge);

    EXCEPTION_ASSERT_WITH_LOG(response.getSW2() == 0x00,
        LibLogicalAccessException, "AuthenticateEV2NonFirst Part 2 failed.");

    EXCEPTION_ASSERT_WITH_LOG(response.getData().size() == 16,
        LibLogicalAccessException, "AuthenticateEV2NonFirst Part 2 returned an invalid RndA' length.");

    const ByteVector rndAPrime = AESHelper::AESDecrypt(response.getData(), keydiv, iv);

    EXCEPTION_ASSERT_WITH_LOG(rndAPrime.size() == 16,
        LibLogicalAccessException, "AuthenticateEV2NonFirst returned an invalid RndA'.");

    // Verify RndA' = RndA rotated left by one byte.
    ByteVector expectedRndAPrime = rndA;
    std::rotate(expectedRndAPrime.begin(), expectedRndAPrime.begin() + 1, expectedRndAPrime.end());

    EXCEPTION_ASSERT_WITH_LOG(rndAPrime == expectedRndAPrime,
        LibLogicalAccessException, "AuthenticateEV2NonFirst authentication failed : invalid RndA'.");

    crypto->generateSessionKey(keydiv, rndA, rndB);

    crypto->d_auth_method  = CryptoMethod::CM_EV2;
    crypto->d_currentKeyNo = keyno;

    crypto->setKey(crypto->d_currentAid, 0, keyno, key);
}

/**
 * \brief Returns the amount of free memory available on the DUOX card
 *
 * The FreeMem command uses MAC communication mode and returns a three byte
 * little-endian MemSize value
 *
 * This implementation intentionally does not delegate to the legacy
 * DESFireEV1ISO7816Commands::getFreeMem() which silently returns 0 for an
 * invalid response length. DUOX treats such a response as a protocol error
 *
 * \return The available free memory in bytes
 * \throws LibLogicalAccessException if the response does not contain exactly three bytes
 */
std::uint32_t DUOXISO7816Commands::freeMem()
{
    constexpr std::size_t FREE_MEM_RESPONSE_SIZE = 3U;

    const auto response = transmit(DFEV1_INS_FREE_MEM);
    const auto &data    = response.getData();

    EXCEPTION_ASSERT_WITH_LOG(data.size() == FREE_MEM_RESPONSE_SIZE,
        LibLogicalAccessException, "DESFire FreeMem returned an invalid response length.");

    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           (static_cast<std::uint32_t>(data[2]) << 16U);
}

DUOXKeySettings DUOXISO7816Commands::getKeySettings(DUOXKeySettingsOption option)
{
    constexpr std::size_t ECC_METADATA_ENTRY_SIZE = 13;
    constexpr std::size_t CA_ROOT_METADATA_ENTRY_SIZE = 10;
    constexpr std::uint8_t MAX_METADATA_ENTRIES = 0x05;
    constexpr std::uint8_t KEY_TYPE_MASK = 0xC0;
    constexpr std::uint8_t KEY_COUNT_MASK = 0x3F;
    constexpr std::uint8_t KEY_TYPE_NA = 0x00;
    constexpr std::uint8_t KEY_TYPE_RESERVED = 0x40;
    constexpr std::uint8_t KEY_TYPE_AES128 = 0x80;
    constexpr std::uint8_t KEY_TYPE_AES256 = 0xC0;

    EXCEPTION_ASSERT_WITH_LOG(
        option == DUOXKeySettingsOption::KeySettings ||
        option == DUOXKeySettingsOption::ECCPrivateKeyMetadata ||
        option == DUOXKeySettingsOption::CARootKeyMetadata,
        LibLogicalAccessException, "Invalid DUOX GetKeySettings option : " + byteToHex(static_cast<std::uint8_t>(option)) +
            ". Supported values are 0x00, 0x01 and 0x02.");

    const auto chip = getDESFireChip();

    EXCEPTION_ASSERT_WITH_LOG(chip != nullptr,
        LibLogicalAccessException, "DUOX GetKeySettings requires an initialized DESFire chip.");

    const auto crypto = chip->getCrypto();

    EXCEPTION_ASSERT_WITH_LOG(crypto != nullptr,
        LibLogicalAccessException, "DUOX GetKeySettings requires an initialized DESFire crypto context.");

    const bool piccLevel = crypto->d_currentAid == DUOX_PICC_LEVEL_AID;

    ByteVector params;
    if (option != DUOXKeySettingsOption::KeySettings)
    {
        params.reserve(1);
        params.push_back(static_cast<std::uint8_t>(option));
    }

    const auto response = transmitDUOX(DUOX_INS_GET_KEY_SETTINGS, params, {}, DUOXCommunicationMode::MAC);

    checkSuccess(response, DUOX_SUCCESS, __func__);

    const ByteVector &data = response.getData();

    DUOXKeySettings result;
    result.piccLevel = piccLevel;

    // TODO refactor later : add a switch per option. Just set code in sub-functions, don't optimize any further
    // Each "if" section should be contained in a proper sub function

    // ECC private key metadata
    if (option == DUOXKeySettingsOption::ECCPrivateKeyMetadata)
    {
        result.responseType = DUOXKeySettingsOption::ECCPrivateKeyMetadata;

        EXCEPTION_ASSERT_WITH_LOG(!data.empty(),
            LibLogicalAccessException, "DUOX GetKeySettings ECC private key metadata response is empty.");

        const std::uint8_t entryCount = data[0];

        EXCEPTION_ASSERT_WITH_LOG(entryCount <= MAX_METADATA_ENTRIES, LibLogicalAccessException,
            "Invalid DUOX ECC private key metadata entry count " + byteToHex(entryCount) +
                ". Maximum supported value is 0x05.");

        const std::size_t expectedSize = 1 + static_cast<std::size_t>(entryCount) * ECC_METADATA_ENTRY_SIZE;

        EXCEPTION_ASSERT_WITH_LOG(data.size() == expectedSize, LibLogicalAccessException,
            "Invalid DUOX ECC private key metadata response length : expected " +
            std::to_string(expectedSize) + " bytes, received " + std::to_string(data.size()) + " bytes.");

        result.eccPrivateKeys.reserve(entryCount);

        std::size_t offset = 1;
        for (std::uint8_t index = 0; index < entryCount; ++index)
        {
            DUOXECCPrivateKeyMetadata entry;

            entry.keyNo = data[offset++];
            const std::uint8_t rawCurveId = data[offset++];

            switch (static_cast<CurveID>(rawCurveId))
            {
            case CurveID::NIST_P256:
            case CurveID::BRAINPOOL_P256R1:
                entry.curveId = static_cast<CurveID>(rawCurveId);
                break;
            default:
                THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
                    "Invalid DUOX ECC private key metadata CurveID " +
                    byteToHex(rawCurveId) + " at entry " + std::to_string(index) + ".");
            }

            entry.keyPolicy = static_cast<std::uint16_t>(data[offset]) | (static_cast<std::uint16_t>(data[offset + 1]) << 8);
            offset += 2;
            entry.writeAccess = data[offset++];
            entry.keyUsageCtrLimit =
                static_cast<std::uint32_t>(data[offset]) |
                (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
                (static_cast<std::uint32_t>(data[offset + 3]) << 24);

            offset += 4;

            entry.keyUsageCtr = static_cast<std::uint32_t>(data[offset]) |
                                (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                                (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
                                (static_cast<std::uint32_t>(data[offset + 3]) << 24);

            offset += 4;

            EXCEPTION_ASSERT_WITH_LOG((entry.keyPolicy & ~KEY_POLICY_VALID_MASK) == 0, LibLogicalAccessException,
                "Invalid DUOX ECC private key metadata KeyPolicy at entry " +
                std::to_string(index) + ": reserved bits are set.");

            EXCEPTION_ASSERT_WITH_LOG((entry.writeAccess & ACCESS_RFU_MASK) == 0, LibLogicalAccessException,
                "Invalid DUOX ECC private key metadata WriteAccess at entry " +
                std::to_string(index) + ": reserved bits are set.");

            result.eccPrivateKeys.push_back(entry);
        }

        EXCEPTION_ASSERT_WITH_LOG(offset == data.size(),
            LibLogicalAccessException, "Internal DUOX GetKeySettings ECC metadata parser error : unexpected trailing data.");

        return result;
    }

    // CA Root Key metadata
    if (option == DUOXKeySettingsOption::CARootKeyMetadata)
    {
        result.responseType = DUOXKeySettingsOption::CARootKeyMetadata;

        EXCEPTION_ASSERT_WITH_LOG(!data.empty(),
            LibLogicalAccessException, "DUOX GetKeySettings CA Root Key metadata response is empty.");

        const std::uint8_t entryCount = data[0];

        EXCEPTION_ASSERT_WITH_LOG(entryCount <= MAX_METADATA_ENTRIES, LibLogicalAccessException,
            "Invalid DUOX CA Root Key metadata entry count " + byteToHex(entryCount) +
            ". Maximum supported value is 0x05.");

        const std::size_t expectedSize = 1 + static_cast<std::size_t>(entryCount) * CA_ROOT_METADATA_ENTRY_SIZE;

        EXCEPTION_ASSERT_WITH_LOG(data.size() == expectedSize, LibLogicalAccessException,
            "Invalid DUOX CA Root Key metadata response length : expected " +
            std::to_string(expectedSize) + " bytes, received " + std::to_string(data.size()) + " bytes.");

        result.caRootKeys.reserve(entryCount);

        std::size_t offset = 1;
        for (std::uint8_t index = 0; index < entryCount; ++index)
        {
            DUOXCARootKeyMetadata entry;

            entry.keyNo = data[offset++];

            const std::uint8_t rawCurveId = data[offset++];

            switch (static_cast<CurveID>(rawCurveId))
            {
            case CurveID::NIST_P256:
            case CurveID::BRAINPOOL_P256R1:
                entry.curveId = static_cast<CurveID>(rawCurveId);
                break;

            default:
                THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
                    "Invalid DUOX CA Root Key metadata CurveID " + byteToHex(rawCurveId) + " at entry " +
                    std::to_string(index) + ".");
            }

            entry.accessRights = static_cast<std::uint16_t>(data[offset]) |
                                 (static_cast<std::uint16_t>(data[offset + 1]) << 8);

            offset += 2;

            entry.writeAccess = data[offset++];
            entry.readAccess = data[offset++];
            entry.crlFile = data[offset++];

            entry.crlFileAid = static_cast<std::uint32_t>(data[offset]) |
                               (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                               (static_cast<std::uint32_t>(data[offset + 2]) << 16);

            offset += 3;

            EXCEPTION_ASSERT_WITH_LOG((entry.accessRights & ~ACCESS_RIGHTS_VALID_MASK) == 0, LibLogicalAccessException,
                "Invalid DUOX CA Root Key metadata AccessRights at entry " +
                std::to_string(index) + ": reserved bits are set.");

            EXCEPTION_ASSERT_WITH_LOG((entry.writeAccess & ACCESS_RFU_MASK) == 0, LibLogicalAccessException,
                "Invalid DUOX CA Root Key metadata WriteAccess at entry " +
                std::to_string(index) + ": reserved bits are set.");

            EXCEPTION_ASSERT_WITH_LOG((entry.readAccess & ACCESS_RFU_MASK) == 0, LibLogicalAccessException,
                "Invalid DUOX CA Root Key metadata ReadAccess at entry " +
                std::to_string(index) + ": reserved bits are set.");

            EXCEPTION_ASSERT_WITH_LOG((entry.crlFile & CRL_FILE_RFU_MASK) == 0, LibLogicalAccessException,
                "Invalid DUOX CA Root Key metadata CRLFile at entry " +
                std::to_string(index) + ": reserved bits are set.");

            const bool crlEnabled = (entry.crlFile & CRL_FILE_ENABLED_MASK) != 0;

            if (!crlEnabled)
            {
                EXCEPTION_ASSERT_WITH_LOG(entry.crlFile == 0x00, LibLogicalAccessException,
                    "Invalid DUOX CA Root Key metadata CRLFile at entry " +
                    std::to_string(index) + ": file number must be zero when CRL is disabled.");

                EXCEPTION_ASSERT_WITH_LOG(entry.crlFileAid == 0x000000, LibLogicalAccessException,
                    "Invalid DUOX CA Root Key metadata CRLFileAID at entry " +
                    std::to_string(index) + ": AID must be zero when CRL is disabled.");
            }

            result.caRootKeys.push_back(entry);
        }

        EXCEPTION_ASSERT_WITH_LOG(offset == data.size(), LibLogicalAccessException,
            "Internal DUOX GetKeySettings CA Root Key metadata parser error : unexpected trailing data.");

        return result;
    }

    //Base KeySettings response
    result.responseType = DUOXKeySettingsOption::KeySettings;

    EXCEPTION_ASSERT_WITH_LOG(data.size() >= 2, LibLogicalAccessException,
        "DUOX GetKeySettings returned an incomplete key-settings response : at least 2 bytes are required.");

    if (piccLevel)
    {
        EXCEPTION_ASSERT_WITH_LOG(data.size() == 2, LibLogicalAccessException,
            "Invalid DUOX PICC GetKeySettings response length : expected exactly 2 bytes, received " +
            std::to_string(data.size()) + " bytes.");
    }
    else
    {
        EXCEPTION_ASSERT_WITH_LOG(data.size() == 2 || data.size() == 6, LibLogicalAccessException,
            "Invalid DUOX application GetKeySettings response length : expected 2 or 6 bytes, received " +
            std::to_string(data.size()) + " bytes.");
    }

    std::size_t offset = 0;

    result.keySettings = data[offset++];
    result.maxNoOfKeys = data[offset++];
    result.keyType = result.maxNoOfKeys & KEY_TYPE_MASK;
    result.numberOfKeys = result.maxNoOfKeys & KEY_COUNT_MASK;

    EXCEPTION_ASSERT_WITH_LOG(result.keyType != KEY_TYPE_RESERVED, LibLogicalAccessException,
        "Invalid DUOX GetKeySettings MaxNoOfKeys : reserved key-type encoding 01b was returned.");

    if (piccLevel)
    {
        EXCEPTION_ASSERT_WITH_LOG(result.numberOfKeys == 0x01, LibLogicalAccessException,
            "Invalid DUOX PICC GetKeySettings MaxNoOfKeys : bits 0-5 must be 0x01, received " +
            byteToHex(result.numberOfKeys) + ".");

        EXCEPTION_ASSERT_WITH_LOG(result.keyType == KEY_TYPE_AES128 || result.keyType == KEY_TYPE_AES256,
            LibLogicalAccessException, "Invalid DUOX PICC GetKeySettings key type : expected AES-128 or AES-256.");
    }
    else
    {
        if (result.numberOfKeys == 0x00)
        {
            EXCEPTION_ASSERT_WITH_LOG(result.keyType == KEY_TYPE_NA, LibLogicalAccessException,
                "Invalid DUOX application GetKeySettings response : an application containing no keys must report "
                "key type 00b.");
        }
        else
        {
            EXCEPTION_ASSERT_WITH_LOG(result.keyType == KEY_TYPE_AES128 || result.keyType == KEY_TYPE_AES256,
                LibLogicalAccessException,
                "Invalid DUOX application GetKeySettings key type : expected AES-128 or AES-256.");
        }
    }

    if (!piccLevel && data.size() == 6)
    {
        result.hasApplicationKeySetSettings = true;
        result.aksVersion = data[offset++];
        result.noKeySets = data[offset++];
        result.maxKeySize = data[offset++];
        result.appKeySetSettings = data[offset++];

        EXCEPTION_ASSERT_WITH_LOG(result.noKeySets >= 0x02 && result.noKeySets <= 0x10, LibLogicalAccessException,
            "Invalid DUOX GetKeySettings NoKeySets value " +
            byteToHex(result.noKeySets) + ": expected a value between 0x02 and 0x10.");

        EXCEPTION_ASSERT_WITH_LOG(result.maxKeySize == 0x10 || result.maxKeySize == 0x20, LibLogicalAccessException,
            "Invalid DUOX GetKeySettings MaxKeySize value " + byteToHex(result.maxKeySize) + ": expected 0x10 or 0x20.");
    }

    EXCEPTION_ASSERT_WITH_LOG(offset == data.size(),
        LibLogicalAccessException, "Internal DUOX GetKeySettings parser error : unexpected trailing data.");

    return result;
}

void DUOXISO7816Commands::changeKey(std::uint8_t keyNo, std::shared_ptr<DESFireKey> newKey)
{
    changeKeyEV2Internal(0x00, keyNo, std::move(newKey), DUOXChangeKeyCommand::ChangeKey);
}

void DUOXISO7816Commands::changeKeyEV2(std::uint8_t keySetNo, std::uint8_t keyNo, std::shared_ptr<DESFireKey> newKey)
{
    changeKeyEV2Internal(keySetNo, keyNo, std::move(newKey), DUOXChangeKeyCommand::ChangeKeyEV2);
}

void DUOXISO7816Commands::changeKeyEV2Internal(std::uint8_t keySetNo, std::uint8_t keyNo,
    std::shared_ptr<DESFireKey> newKey, DUOXChangeKeyCommand commandType)
{
    const bool isChangeKey = commandType == DUOXChangeKeyCommand::ChangeKey;

    const char *functionName = isChangeKey ? "DUOX ChangeKey" : "DUOX ChangeKeyEV2";

    auto chip = getDESFireChip();

    EXCEPTION_ASSERT_WITH_LOG(chip != nullptr,
        LibLogicalAccessException, std::string(functionName) + " requires an initialized DESFire chip.");

    auto crypto = std::dynamic_pointer_cast<DESFireEV2Crypto>(chip->getCrypto());

    EXCEPTION_ASSERT_WITH_LOG(crypto != nullptr,
        LibLogicalAccessException, std::string(functionName) + " requires DESFireEV2 crypto.");

    EXCEPTION_ASSERT_WITH_LOG(newKey != nullptr,
        LibLogicalAccessException, std::string(functionName) + " requires a valid new key.");

    EXCEPTION_ASSERT_WITH_LOG((keySetNo & 0xF0) == 0,
        LibLogicalAccessException, std::string(functionName) + " KeySetNo must use bits 0-3 only.");

    // Keep a private copy. The host-side key store is modified only after the card has successfully accepted ChangeKey
    const auto key = std::make_shared<DESFireKey>(*newKey);

    // This checks only if key type is AES. It does NOT distinguish AES-128 from AES-256
    EXCEPTION_ASSERT_WITH_LOG(key->getKeyType() == DESFireKeyType::DF_KEY_AES,
        LibLogicalAccessException, std::string(functionName) + " requires an AES key.");

    const ByteVector keyData = key->getData();

    EXCEPTION_ASSERT_WITH_LOG(keyData.size() == 16 || keyData.size() == 32,
        LibLogicalAccessException, std::string(functionName) + " requires a 16-byte or 32-byte AES key.");

    const bool piccLevel = crypto->d_currentAid == DUOX_PICC_LEVEL_AID;

    const std::uint8_t targetKeyNo = static_cast<std::uint8_t>(keyNo & 0x3F);

    if (piccLevel)
        EXCEPTION_ASSERT_WITH_LOG(keySetNo == 0x00,
            LibLogicalAccessException, std::string(functionName) + " requires KeySetNo = 0 at PICC level.");
    
    // Determined before ChangeKey is transmitted because changing the authenticated key invalidates the authentication
    // For ChangeKeyEV2, KeySetNo != 0 always uses the "different key" encoding
    const bool changingAuthenticatedKey = keySetNo == 0x00 && targetKeyNo == crypto->d_currentKeyNo;

    const bool authenticatedEV2 = crypto->d_auth_method == CryptoMethod::CM_EV2;

    std::uint8_t commandKeyNo = keyNo;

    const bool piccMasterKey = piccLevel && targetKeyNo == 0x00;

    // bits 6 to 7
    if (piccMasterKey)
        commandKeyNo = static_cast<std::uint8_t>(targetKeyNo | (keyData.size() == 16 ? 0x80 : 0xC0));

    const auto oldKey = crypto->getKey(keySetNo, targetKeyNo);

    const ByteVector oldKeyDiversify = oldKey != nullptr ? getKeyInformations(oldKey, targetKeyNo) : ByteVector();

    const ByteVector newKeyDiversify = getKeyInformations(key, targetKeyNo);

    const ByteVector keyDataPlain = crypto->buildDUOXChangeKeyData(keySetNo, commandKeyNo, oldKeyDiversify, key, newKeyDiversify);

    const ByteVector params = isChangeKey ? ByteVector{commandKeyNo} : ByteVector{keySetNo, commandKeyNo};

    const std::uint8_t instruction = isChangeKey ? DUOX_INS_CHANGE_KEY : DUOX_INS_CHANGE_KEY_EV2;

    ISO7816Response response;
    if (!authenticatedEV2)
    {
        // Not authenticated / no EV2 secure messaging
        response = transmitDUOX(instruction, params, keyDataPlain, DUOXCommunicationMode::Plain);
    }
    else if (changingAuthenticatedKey)
    {
        // EV2 secure messaging applies but plain response because ChangeKey invalidates the authentication
        ByteVector integrityInput;
        integrityInput.reserve(1 + params.size());
        integrityInput.push_back(instruction);
        integrityInput.insert(integrityInput.end(), params.begin(), params.end());

        const ByteVector securedData = crypto->desfireEncrypt(keyDataPlain, integrityInput);

        // The response must NOT be processed with the EV2 session because
        // changing the authenticated key invalidates that authentication
        ByteVector command;
        command.reserve(params.size() + securedData.size());
        command.insert(command.end(), params.begin(), params.end());
        command.insert(command.end(), securedData.begin(), securedData.end());

        response = DESFireISO7816Commands::transmit(instruction, command);
    }
    else
    {
        // Normal EV2 CommMode.Full where command is protected and response is MAC-protected/decrypted
        response = transmitDUOX(instruction, params, keyDataPlain, DUOXCommunicationMode::Full);
    }

    checkSuccess(response, DUOX_SUCCESS, __func__);

    // The card accepted the operation, therefore update the local crypto key store
    crypto->setKey(crypto->d_currentAid, keySetNo, targetKeyNo, key);

    // ChangeKey of the authenticated key invalidates EV2 authentication
    if (changingAuthenticatedKey)
        crypto->invalidateAuthentication();
}

// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------

void DUOXISO7816Commands::isoGeneralAuthenticate(
    std::uint8_t caRootKeyNo, std::uint8_t secondaryCaRootKeyNo, CurveID curve,
    bool mutualAuthentication, bool certificatePresent, std::uint8_t certFileNo,
    std::uint8_t privateKeyNo, const ByteVector &privateKey,
    const ByteVector &certificate)
{
    auto &auth = d_duoxECCAuthentication;

    EXCEPTION_ASSERT_WITH_LOG(!auth.active,
        LibLogicalAccessException, "DUOX ECC authentication is already in progress.");

    EXCEPTION_ASSERT_WITH_LOG(caRootKeyNo <= 0x07,
        LibLogicalAccessException, "DUOX CA Root Key number must fit into P2 bits 0-2.");

    EXCEPTION_ASSERT_WITH_LOG(secondaryCaRootKeyNo <= 0x07,
        LibLogicalAccessException, "DUOX secondary CA Root Key number must fit into P2 bits 4-6.");

    if (mutualAuthentication)
    {
        EXCEPTION_ASSERT_WITH_LOG(privateKeyNo <= 0x07,
            LibLogicalAccessException, "DUOX private key number must fit into bits 0-2.");

        EXCEPTION_ASSERT_WITH_LOG(!privateKey.empty(),
            LibLogicalAccessException, "DUOX mutual authentication requires a reader private key.");

        const std::size_t coordinateSize = getCoordinateSize(curve);

        EXCEPTION_ASSERT_WITH_LOG(privateKey.size() == coordinateSize,
            LibLogicalAccessException, "Invalid DUOX reader private key size.");
    }
    else
    {
        // PrivateKeyNo and Priv.A are not used for reader-unilateral authentication
        EXCEPTION_ASSERT_WITH_LOG(privateKey.empty(),
            LibLogicalAccessException, "Reader private key must be omitted for unilateral authentication.");
    }

    if (certificatePresent)
    {
        EXCEPTION_ASSERT_WITH_LOG(!certificate.empty(),
            LibLogicalAccessException, "Cert.A is required when certificate authentication is enabled.");

        EXCEPTION_ASSERT_WITH_LOG(certificate.size() <= 880,
            LibLogicalAccessException, "DUOX Certificate.A exceeds the maximum supported certificate size.");
    }
    else
    {
        EXCEPTION_ASSERT_WITH_LOG(certificate.empty(),
            LibLogicalAccessException, "Cert.A must be empty when certificate authentication is disabled.");
    }

    /*
     * Part 1 creates the authentication state.
     *
     * Part 2 MUST immediately follow it. No other card command is permitted between the two commands
     */
    try
    {
        isoGeneralAuthenticatePart1(caRootKeyNo, secondaryCaRootKeyNo, curve, mutualAuthentication,
                                    certificatePresent, certFileNo, privateKeyNo);
        isoGeneralAuthenticatePart2(privateKey, certificate);
    }
    catch (...)
    {
        /*
         * Authentication context is invalid after any failure.
         *
         * This also guarantees that ephemeral private material is released after a failed authentication
         */
        auth = DUOXECCAuthenticationState{};
        throw;
    }
}

void DUOXISO7816Commands::isoGeneralAuthenticatePart1(
    std::uint8_t caRootKeyNo, std::uint8_t secondaryCaRootKeyNo, CurveID curve,
    bool mutualAuthentication, bool certificatePresent, std::uint8_t certFileNo,
    std::uint8_t privateKeyNo)
{
    printInfo("=== ISOGeneralAuthenticate Part 1 DEBUG ===");

    if (mutualAuthentication)
        EXCEPTION_ASSERT_WITH_LOG(privateKeyNo <= 0x07,
            LibLogicalAccessException, "DUOX private key number must fit into bits 0-2.");

    const std::uint8_t authMethod = mutualAuthentication
                                        ? (certificatePresent ? 0x80 : 0xA0)
                                        : (certificatePresent ? 0x40 : 0x60);

    const ByteVector optsA = buildDUOXOptsA(mutualAuthentication, certificatePresent, certFileNo, privateKeyNo);

    if (mutualAuthentication && certificatePresent)
        EXCEPTION_ASSERT_WITH_LOG(optsA.size() == 6,
            LibLogicalAccessException, "Unexpected OptsA size for mutual authentication with certificate.");

    /*
     * Generate :
     *   E.Priv.A
     *   E.Pub.A
     * The private key must never leave the authentication state
     */
    const ECKeyPair ephemeralKeyPair = generateECKeyPair(curve);

    EXCEPTION_ASSERT_WITH_LOG(validateECPoint(curve, ephemeralKeyPair.publicKey),
        LibLogicalAccessException, "Generated DUOX ephemeral public key is invalid.");

    const ByteVector encodedEphemeralA = encodeECPoint(curve, ephemeralKeyPair.publicKey);

    EXCEPTION_ASSERT_WITH_LOG(encodedEphemeralA.size() == 65,
        LibLogicalAccessException, "P-256 E.Pub.A must be exactly 65 bytes.");

    EXCEPTION_ASSERT_WITH_LOG(encodedEphemeralA[0] == 0x04,
        LibLogicalAccessException, "E.Pub.A must use uncompressed point representation.");

    const ByteVector authenticationData = buildDUOXAuthenticationData(encodedEphemeralA);

    EXCEPTION_ASSERT_WITH_LOG(authenticationData.size() == 69,
        LibLogicalAccessException, "DUOX AuthenticationData must be 69 bytes.");

    const std::uint8_t p2 = buildDUOXGeneralAuthenticateP2(caRootKeyNo, secondaryCaRootKeyNo, true);

    ByteVector commandData;
    commandData.reserve(optsA.size() + authenticationData.size());

    commandData.insert(commandData.end(), optsA.begin(), optsA.end());
    commandData.insert(commandData.end(), authenticationData.begin(), authenticationData.end());

    // Part 1 normally fits in a short APDU (use the extended path if necessary)
    EXCEPTION_ASSERT_WITH_LOG(commandData.size() <= 0xFFFF,
        LibLogicalAccessException, "DUOX ISOGeneralAuthenticate Part 1 command is too large.");

    printInfo("Part 1 : mutual=" + std::to_string(mutualAuthentication) +
              ", certificate=" + std::to_string(certificatePresent) +
              ", CA root=" + std::to_string(caRootKeyNo) +
              ", secondary CA root=" + std::to_string(secondaryCaRootKeyNo) +
              ", curve=" + std::to_string(static_cast<unsigned int>(curve)) +
              ", certFileNo=" + std::to_string(certFileNo) +
              ", privateKeyNo=" + std::to_string(privateKeyNo));

    debugBytes("Part 1 : OptsA", optsA);

    printInfo("Part 1 : sending General Authenticate, Lc=" +
              std::to_string(commandData.size()) + ", P2=0x" + hexDump(ByteVector{p2}));

    const ISO7816Response response = sendDUOXGeneralAuthenticate(p2, commandData, 0x0000); // TODO change Le later

    const std::uint8_t sw1 = response.getSW1();
    const std::uint8_t sw2 = response.getSW2();
    const bool success = sw1 == 0x90 && sw2 == 0x00;
    const bool versionFallback = sw1 == 0x9F && sw2 == 0x00;

    EXCEPTION_ASSERT_WITH_LOG(success || versionFallback,
        LibLogicalAccessException, "DUOX ISOGeneralAuthenticate Part 1 failed.");

    printInfo("Part 1 : response SW=0x" + hexDump(ByteVector{sw1, sw2}) +
              ", data=" + std::to_string(response.getData().size()) + " bytes.");

    const ECPoint ephemeralPublicB = parseDUOXAuthenticationResponse(response.getData(), curve);
    const ByteVector encodedEphemeralB = encodeECPoint(curve, ephemeralPublicB);

    EXCEPTION_ASSERT_WITH_LOG(encodedEphemeralB.size() == 65,
        LibLogicalAccessException, "PICC E.Pub.B must be exactly 65 bytes.");

    EXCEPTION_ASSERT_WITH_LOG(encodedEphemeralB[0] == 0x04,
        LibLogicalAccessException, "PICC E.Pub.B must be uncompressed.");

    EXCEPTION_ASSERT_WITH_LOG(validateECPoint(curve, ephemeralPublicB),
        LibLogicalAccessException, "PICC returned an invalid E.Pub.B point.");

     // ECDH : ShS = ECDH(E.Priv.A, E.Pub.B)
    const ByteVector sharedSecret = deriveECDHSharedSecret(curve, ephemeralKeyPair.privateKey, ephemeralPublicB);

    EXCEPTION_ASSERT_WITH_LOG(!sharedSecret.empty(),
        LibLogicalAccessException, "DUOX ECDH produced an empty shared secret.");

    // Derive K_SESAuthENC K_SESAuthMAC
    const SessionKeys sessionKeys = deriveSessionKeys(ephemeralKeyPair.publicKey, ephemeralPublicB, sharedSecret);

    EXCEPTION_ASSERT_WITH_LOG(sessionKeys.encKey.size() == 16,
        LibLogicalAccessException, "DUOX session ENC key must be 16 bytes.");

    EXCEPTION_ASSERT_WITH_LOG(sessionKeys.macKey.size() == 16,
        LibLogicalAccessException, "DUOX session MAC key must be 16 bytes.");

    DUOXECCAuthenticationState newAuth;
    newAuth.active               = true;
    newAuth.curve                = curve;
    newAuth.mutualAuthentication = mutualAuthentication;
    newAuth.certificatePresent   = certificatePresent;
    newAuth.caRootKeyNo          = caRootKeyNo;
    newAuth.secondaryCaRootKeyNo = secondaryCaRootKeyNo;
    newAuth.certFileNo   = certFileNo;
    newAuth.privateKeyNo = privateKeyNo;
    newAuth.optsA = optsA;
    newAuth.ephemeralPrivateKey = ephemeralKeyPair.privateKey;
    newAuth.ephemeralPublicA    = ephemeralKeyPair.publicKey;
    newAuth.ephemeralPublicB    = ephemeralPublicB;
    newAuth.sessionKeys = sessionKeys;

    d_duoxECCAuthentication = std::move(newAuth);

    printInfo("Part 1 completed : certificatePresent=" + std::to_string(d_duoxECCAuthentication.certificatePresent));
    printInfo("=== ISOGeneralAuthenticate Part 1 DEBUG COMPLETE ===");
}

//TODO Keeping this here temporarily for readability. Will be refactored and correctly integrated into the project later.
namespace 
{
ByteVector padDUOXAES(const ByteVector &data)
{
    constexpr std::size_t blockSize = 16;

    ByteVector padded = data;

    const std::size_t padding = blockSize - (padded.size() % blockSize);

    padded.push_back(0x80);
    padded.insert(padded.end(), padding - 1, 0x00);

    return padded;
}

ByteVector unpadDUOXAES(const ByteVector &data)
{
    EXCEPTION_ASSERT_WITH_LOG(!data.empty() && data.size() % 16 == 0,
        LibLogicalAccessException, "Invalid DUOX AES padded data.");

    std::size_t pos = data.size();

    while (pos > 0 && data[pos - 1] == 0x00)
        --pos;

    EXCEPTION_ASSERT_WITH_LOG(pos > 0 && data[pos - 1] == 0x80,
        LibLogicalAccessException, "Invalid DUOX AES padding.");

    return ByteVector(data.begin(), data.begin() + pos - 1);
}

}
void DUOXISO7816Commands::isoGeneralAuthenticatePart2(const ByteVector &privateKey, const ByteVector &certificate)
{
    printInfo("Executing ISOGeneralAuthenticate Part 2.");

    auto &auth = d_duoxECCAuthentication;

    EXCEPTION_ASSERT_WITH_LOG(auth.active,LibLogicalAccessException,
                              "DUOX ISOGeneralAuthenticatePart2 called without an active ISOGeneralAuthenticate Part 1.");

    const bool certAExpected = auth.certificatePresent;
    const bool certAProvided = !certificate.empty();

    EXCEPTION_ASSERT_WITH_LOG(
        certAExpected == certAProvided,LibLogicalAccessException,
        (certAExpected
             ? "DUOX Part 2 requires Cert.A, but no certificate was provided."
             : "DUOX Part 2 must omit Cert.A, but a certificate was provided."));

    // Part 1 has already established the curve
    const CurveID curve              = auth.curve;
    const std::size_t coordinateSize = getCoordinateSize(auth.curve);

    EXCEPTION_ASSERT_WITH_LOG(privateKey.size() == coordinateSize,
        LibLogicalAccessException, "DUOX static private key does not match the authentication curve.");

    // In the no-Cert.A variants the caller must not provide a certificate
    if (certAExpected)
    {
        EXCEPTION_ASSERT_WITH_LOG(certificate.size() <= 880,
            LibLogicalAccessException, "DUOX Certificate.A exceeds the maximum supported certificate chain size.");

        EXCEPTION_ASSERT_WITH_LOG(certificate.size() >= 4,
            LibLogicalAccessException, "DUOX Cert.A is too short to be a DER certificate.");

        EXCEPTION_ASSERT_WITH_LOG(certificate[0] == 0x30,
            LibLogicalAccessException, "DUOX Cert.A does not start with a DER SEQUENCE.");
    }
    else
        EXCEPTION_ASSERT_WITH_LOG(certificate.empty(),
            LibLogicalAccessException, "Certificate.A must be omitted for this authentication variant.");

    printInfo("Part 2 : certificate=" + std::string(certAExpected ? "present" : "omitted") +
        ", Cert.A size=" + std::to_string(certificate.size()) +
        ", private key size=" + std::to_string(privateKey.size()));

    const ByteVector encodedPublicA = encodeECPoint(curve, auth.ephemeralPublicA);
    const ByteVector encodedPublicB = encodeECPoint(curve, auth.ephemeralPublicB);

    printInfo("E.Pub.A = " + hexDump(encodedPublicA));
    printInfo("E.Pub.B = " + hexDump(encodedPublicB));
    printInfo("E.Pub.A.x = " + hexDump(ByteVector(encodedPublicA.begin() + 1, encodedPublicA.begin() + 33)));
    printInfo("E.Pub.B.x = " + hexDump(ByteVector(encodedPublicB.begin() + 1, encodedPublicB.begin() + 33)));

    ByteVector signedMessage;
    signedMessage.reserve(2 + auth.optsA.size() + encodedPublicA.size() + encodedPublicB.size());

    signedMessage.push_back(0xE0);
    signedMessage.push_back(0xE0);
    signedMessage.insert(signedMessage.end(), auth.optsA.begin(), auth.optsA.end());
    signedMessage.insert(signedMessage.end(), encodedPublicA.begin(), encodedPublicA.end());
    signedMessage.insert(signedMessage.end(), encodedPublicB.begin(), encodedPublicB.end());

    // Generate ECDSA signature using the static reader private key.
    // performDUOXECDSASign() performs SHA-256 internally
    const ECDSASignature signature = signECDSA(curve, privateKey, signedMessage);

    EXCEPTION_ASSERT_WITH_LOG(signature.r.size() == 32 && signature.s.size() == 32,
        LibLogicalAccessException, "DUOX ECDSA signature has an invalid size.");

    // The signature in Msg.A.pl is DER encoded
    const ByteVector encodedSignature = encodeECDSASignatureDER(signature);

    EXCEPTION_ASSERT_WITH_LOG(!encodedSignature.empty(),
        LibLogicalAccessException, "Unable to encode DUOX ECDSA signature.");

    // TEST ONLY (verify the signature using the public key from the exact Cert.A that we are about to send to the card
    verifySignatureWithCertificate(certificate, signedMessage, signature);

    ByteVector plaintext;
    plaintext.reserve(2 + (auth.certificatePresent ? certificate.size() : 0) + encodedSignature.size());

    plaintext.push_back(0xE0);
    plaintext.push_back(0xE0);
    if (auth.certificatePresent)
        plaintext.insert(plaintext.end(), certificate.begin(), certificate.end());
    plaintext.insert(plaintext.end(), encodedSignature.begin(), encodedSignature.end());

    const std::size_t expectedPlaintextSize = 2 + (certAExpected ? certificate.size() : 0) + encodedSignature.size();

    if (plaintext.size() != expectedPlaintextSize)
    {
        throw std::runtime_error("Msg.A.pl size mismatch: expected " +
            std::to_string(expectedPlaintextSize) + ", got " + std::to_string(plaintext.size()) + ".");
    }
    if (plaintext[0] != 0xE0 || plaintext[1] != 0xE0)
        throw std::runtime_error("Msg.A.pl does not start with E0 E0.");
    const std::size_t signatureOffset = 2 + (certAExpected ? certificate.size() : 0);

    if (!std::equal(certificate.begin(), certificate.end(), plaintext.begin() + 2))
        throw std::runtime_error("Cert.A embedded in Msg.A.pl does not match the supplied certificate.");

    if (!std::equal(encodedSignature.begin(), encodedSignature.end(), plaintext.begin() + signatureOffset))
        throw std::runtime_error("Sig.A embedded in Msg.A.pl does not match generated Sig.A.");

    if (!certAExpected && plaintext.size() != 2 + encodedSignature.size())
        throw std::runtime_error("Msg.A.pl contains unexpected Cert.A bytes.");

    printInfo("Part 2: Msg.A.pl=" + std::to_string(plaintext.size()) +
              " bytes, Cert.A=" + std::to_string(certAExpected ? certificate.size() : 0) +
              " bytes, Sig.A=" + std::to_string(encodedSignature.size()) + " bytes.");

    const ByteVector paddedPlaintext = padDUOXAES(plaintext);
    const ByteVector iv(16, 0x00);

    printInfo("=== DUOX AUTH CRYPTO DEBUG ===");
    printInfo("E.Pub.A = " + hexDump(encodedPublicA));
    printInfo("E.Pub.B = " + hexDump(encodedPublicB));

    const ByteVector xA(encodedPublicA.begin() + 1, encodedPublicA.begin() + 33);
    const ByteVector xB(encodedPublicB.begin() + 1, encodedPublicB.begin() + 33);
    const ByteVector xALast8(xA.end() - 8, xA.end());
    const ByteVector xBLast8(xB.end() - 8, xB.end());
    const ByteVector kdfSalt = [&]()
    {
        ByteVector v;
        v.reserve(16);
        v.insert(v.end(), xALast8.begin(), xALast8.end());
        v.insert(v.end(), xBLast8.begin(), xBLast8.end());
        return v;
    }();

    printInfo("E.Pub.A.x[7..0] = " + hexDump(xALast8));
    printInfo("E.Pub.B.x[7..0] = " + hexDump(xBLast8));
    printInfo("KDF salt         = " + hexDump(kdfSalt));
    printInfo("K_SES_AUTH_ENC    = " + hexDump(auth.sessionKeys.encKey));
    printInfo("K_SES_AUTH_MAC    = " + hexDump(auth.sessionKeys.macKey));
    printInfo("Msg.A.pl          = " + hexDump(plaintext));
    printInfo("Msg.A.pl size      = " + std::to_string(plaintext.size()));
    printInfo("Msg.A.padded      = " + hexDump(paddedPlaintext));

    const ByteVector encryptedMessage = AESHelper::AESEncrypt(paddedPlaintext, auth.sessionKeys.encKey, iv);

    printInfo("Msg.A.enc         = " + hexDump(encryptedMessage));
    printInfo("=== DUOX AUTH CRYPTO DEBUG COMPLETE ===");

    EXCEPTION_ASSERT_WITH_LOG(!encryptedMessage.empty() && encryptedMessage.size() % 16 == 0,
        LibLogicalAccessException, "DUOX encrypted authentication message has an invalid length.");

    auto msgATLV = std::make_shared<TLV>(0x86);
    msgATLV->value(encryptedMessage);

    auto authDO = std::make_shared<TLV>(0x7C);

    authDO->value(msgATLV);

    const ByteVector commandData = authDO->compute_der();

    EXCEPTION_ASSERT_WITH_LOG(commandData.size() <= 0xFFFF,
        LibLogicalAccessException, "DUOX Part 2 authentication data is too large.");

    EXCEPTION_ASSERT_WITH_LOG(commandData.size() >= 2, LibLogicalAccessException,
                              "Invalid DUOX Part 2 authentication data.");

    printInfo("Part 2: sending General Authenticate, Lc=" +
              std::to_string(commandData.size()) + ".");

    ////// TEST /////
    const ByteVector decrypted = AESHelper::AESDecrypt(encryptedMessage, auth.sessionKeys.encKey, iv);
    const ByteVector unpadded = unpadDUOXAES(decrypted);
    if (unpadded != plaintext)
    {
        throw std::runtime_error("Local DUOX Msg.A AES round-trip failed.");
    }
    printInfo("Local Msg.A AES encryption/decryption round-trip verified.");
    /////////////////

    const ISO7816Response response = sendDUOXGeneralAuthenticate(0x00, commandData, 0x0000);

    const std::uint8_t sw1 = response.getSW1();
    const std::uint8_t sw2 = response.getSW2();

    // Part 2 only accepts ISO 9000 as successful completion
    EXCEPTION_ASSERT_WITH_LOG(sw1 == 0x90 && sw2 == 0x00,
        LibLogicalAccessException, "DUOX ISOGeneralAuthenticatePart2 failed.");

    const ByteVector responseData = response.getData();

    auto responseTLVs = TLV::parse_tlvs_der(responseData);

    EXCEPTION_ASSERT_WITH_LOG(responseTLVs.size() == 1,
        LibLogicalAccessException, "DUOX ISOGeneralAuthenticatePart2 returned an invalid authentication data structure.");

    EXCEPTION_ASSERT_WITH_LOG(responseTLVs[0]->tag() == 0x7C,
        LibLogicalAccessException, "DUOX ISOGeneralAuthenticatePart2 returned an invalid authentication data object tag.");

    auto responseAuthenticationTLVs = TLV::parse_tlvs_der(responseTLVs[0]->value());

    EXCEPTION_ASSERT_WITH_LOG(responseAuthenticationTLVs.size() == 1, LibLogicalAccessException,
        "DUOX ISOGeneralAuthenticatePart2 returned an invalid authentication data object count.");

    EXCEPTION_ASSERT_WITH_LOG(responseAuthenticationTLVs[0]->tag() == 0x82,
        LibLogicalAccessException, "DUOX ISOGeneralAuthenticatePart2 returned an invalid Msg.B.enc tag.");

    const ByteVector encryptedMsgB = responseAuthenticationTLVs[0]->value();

    EXCEPTION_ASSERT_WITH_LOG(!encryptedMsgB.empty() && encryptedMsgB.size() % 16 == 0,
        LibLogicalAccessException, "DUOX Msg.B.enc has an invalid encrypted length.");

    const ByteVector paddedMsgB =
        AESHelper::AESDecrypt(encryptedMsgB, auth.sessionKeys.encKey, iv);

    const ByteVector msgB = unpadDUOXAES(paddedMsgB);

    EXCEPTION_ASSERT_WITH_LOG(msgB.size() >= 2,
        LibLogicalAccessException, "DUOX decrypted Msg.B is too short.");

    EXCEPTION_ASSERT_WITH_LOG(msgB[0] == 0xE1 && msgB[1] == 0xE1,
        LibLogicalAccessException, "DUOX Msg.B has an invalid protocol marker.");

    EXCEPTION_ASSERT_WITH_LOG(msgB.size() >= 3,
        LibLogicalAccessException, "DUOX Msg.B is missing OptsB.");

    const std::size_t optsBLength = msgB[2];

    EXCEPTION_ASSERT_WITH_LOG(msgB.size() >= 3 + optsBLength,
        LibLogicalAccessException, "DUOX Msg.B contains a truncated OptsB.");

    ByteVector optsB(msgB.begin() + 2, msgB.begin() + 3 + optsBLength);

    const std::size_t msgBPayloadOffset = 3 + optsBLength;

    printInfo("Part 2: received Msg.B.enc=" + std::to_string(encryptedMsgB.size()) +
              " bytes, OptsB=" + std::to_string(optsB.size()) + " bytes.");

    if (auth.mutualAuthentication)
    {
        EXCEPTION_ASSERT_WITH_LOG(
            msgB.size() > msgBPayloadOffset,
            LibLogicalAccessException, "DUOX mutual authentication response is missing Cert.B/Sig.B.");

        printInfo("Part 2: mutual authentication response contains Cert.B/Sig.B payload (" +
                  std::to_string(msgB.size() - msgBPayloadOffset) + " bytes).");
    }
    else
    {
        EXCEPTION_ASSERT_WITH_LOG(
            msgB.size() == msgBPayloadOffset,
            LibLogicalAccessException, "DUOX reader-unilateral authentication returned unexpected additional data.");
    }

    printInfo("ISOGeneralAuthenticate Part 2 completed.");
}

ISO7816Response DUOXISO7816Commands::sendDUOXGeneralAuthenticate(std::uint8_t p2,
                                                                 const ByteVector &data,
                                                                 std::uint16_t le)
{
    auto adapter = getISO7816ReaderCardAdapter();

    EXCEPTION_ASSERT_WITH_LOG(adapter != nullptr,
        LibLogicalAccessException, "ISO7816 reader/card adapter is required.");

    EXCEPTION_ASSERT_WITH_LOG(data.size() <= 0xFFFF,
        LibLogicalAccessException, "DUOX General Authenticate data is too large.");

    printInfo("sendDUOXGeneralAuthenticate() :");
    printInfo(" CLA = 00");
    printInfo(" INS = 87");
    printInfo(" P1  = 00");
    printInfo(" P2  = " + hexDump(ByteVector{p2}));
    printInfo(" Lc  = " + std::to_string(data.size()));
    debugBytes(" Data", data);
    printInfo(" Le  = 00 00");

    if (data.size() <= 0xFF && le <= 0xFF)
    {
        printInfo("Using normal length APDU: Lc=" + std::to_string(data.size()) + ", Le=" + std::to_string(le));

        return adapter->sendAPDUCommand(ISO7816_CLA_ISO_COMPATIBLE, ISO7816_INS_GENERAL_AUTHENTICATE, 0x00, p2,
                                        static_cast<unsigned char>(data.size()), data, static_cast<unsigned char>(le));
    }
    
    printInfo("Using extended-length APDU: Lc=" + std::to_string(data.size()) + ", Le=" + std::to_string(le));
    return adapter->sendExtendedAPDUCommand(ISO7816_CLA_ISO_COMPATIBLE, ISO7816_INS_GENERAL_AUTHENTICATE, 0x00, p2,
                                            static_cast<unsigned short>(data.size()), data, le);
}

std::uint8_t DUOXISO7816Commands::buildDUOXGeneralAuthenticateP2(std::uint8_t caRootKeyNo,
                                                    std::uint8_t secondaryCaRootKeyNo,
                                                    bool multipleApplicationSelection)
{
    EXCEPTION_ASSERT_WITH_LOG(caRootKeyNo <= 0x07,
        LibLogicalAccessException, "Invalid DUOX CA root key number.");

    if (multipleApplicationSelection)
        EXCEPTION_ASSERT_WITH_LOG(secondaryCaRootKeyNo <= 0x07,
            LibLogicalAccessException, "Invalid DUOX secondary CA root key number.");

    return static_cast<std::uint8_t>(caRootKeyNo | (multipleApplicationSelection ?
        static_cast<std::uint8_t>(secondaryCaRootKeyNo << 4) : 0x00));
}

ByteVector DUOXISO7816Commands::buildDUOXOptsA(bool mutualAuthentication, bool certificateAIncluded,
                                               std::uint8_t certificateFileNo, std::uint8_t privateKeyNo)
{
    std::uint8_t authMethod;

    if (mutualAuthentication)
    {
        authMethod = certificateAIncluded ? 0x80 : 0xA0;
    }
    else
    {
        authMethod = certificateAIncluded ? 0x40 : 0x60;
    }

    ByteVector value;
    value.push_back(authMethod);
    value.push_back(0x00); // ProtocolVersion

    if (mutualAuthentication)
    {
        value.push_back(certificateFileNo);
        value.push_back(privateKeyNo);
    }

    ByteVector result;
    result.push_back(0x80);
    result.push_back(static_cast<std::uint8_t>(value.size())); // For OptsA length is currently only 2 or 4
    result.insert(result.end(), value.begin(), value.end());

    return result;
}

ByteVector DUOXISO7816Commands::buildDUOXAuthenticationData(const ByteVector &ephemeralPublicKey)
{
    EXCEPTION_ASSERT_WITH_LOG(ephemeralPublicKey.size() == 65,
        LibLogicalAccessException, "DUOX ephemeral public key must contain 65 bytes.");

    ByteVector result;

    // Authentication Data Objects header
    result.push_back(0x7C);
    result.push_back(0x43);

    // E.Pub.A
    result.push_back(0x85);
    result.push_back(0x41);

    result.insert(result.end(), ephemeralPublicKey.begin(), ephemeralPublicKey.end());

    return result;
}

// TODO Outdated. Refactor after Part2 is completely refactored.
ECPoint DUOXISO7816Commands::parseDUOXAuthenticationResponse(const ByteVector &response, CurveID curve)
{
    const auto tlvs = TLV::parse_tlvs_der(response, true);

    EXCEPTION_ASSERT_WITH_LOG(tlvs.size() == 1,
        LibLogicalAccessException, "Expected exactly one DUOX authentication TLV.");

    auto authDO = tlvs[0];

    EXCEPTION_ASSERT_WITH_LOG(authDO->tag() == 0x7C,
        LibLogicalAccessException, "Expected DUOX authentication data object 7C.");

    const auto children = TLV::parse_tlvs_der(authDO->value(), true);

    EXCEPTION_ASSERT_WITH_LOG(children.size() == 1,
        LibLogicalAccessException, "Expected exactly one DUOX authentication child.");

    EXCEPTION_ASSERT_WITH_LOG(children[0]->tag() == 0x85,
        LibLogicalAccessException, "Expected DUOX E.Pub.B tag 85.");

    const ByteVector encodedPoint = children[0]->value();

    EXCEPTION_ASSERT_WITH_LOG(encodedPoint.size() == 65,
        LibLogicalAccessException, "DUOX E.Pub.B must contain 65 bytes.");

    const ECPoint point = decodeECPoint(curve, encodedPoint);
    return point;
}

// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------


// -------------------------------------------------------------------------
// DESFire EV2
// -------------------------------------------------------------------------

//TODO Merge later between EV2/EV3 usage and DUOX usage
/*void DUOXISO7816Commands::changeKeyEV2(uint8_t keyset, uint8_t keyno,
                                       std::shared_ptr<DESFireKey> key)
{
    DESFireEV3ISO7816Commands::changeKeyEV2(keyset, keyno, key);
}*/

void DUOXISO7816Commands::authenticateEV2First(uint8_t keyno,
                                               std::shared_ptr<DESFireKey> key)
{
    DESFireEV3ISO7816Commands::authenticateEV2First(keyno, key);
}

void DUOXISO7816Commands::sam_authenticateEV2First(uint8_t keyno,
                                                   std::shared_ptr<DESFireKey> key)
{
    DESFireEV3ISO7816Commands::sam_authenticateEV2First(keyno, key);
}

void DUOXISO7816Commands::createApplication(
    unsigned int aid, DESFireKeySettings settings, unsigned char maxNbKeys,
    DESFireKeyType cryptoMethod, FidSupport fidSupported, unsigned short isoFID,
    ByteVector isoDFName, unsigned char numberKeySets, unsigned char maxKeySize,
    unsigned char actualkeySetVersion, unsigned char rollkeyno,
    bool specificCapabilityData, bool specificVCKeys)
{
    DESFireEV3ISO7816Commands::createApplication(
        aid, settings, maxNbKeys, cryptoMethod, fidSupported, isoFID, isoDFName,
        numberKeySets, maxKeySize, actualkeySetVersion, rollkeyno, specificCapabilityData,
        specificVCKeys);
}

void DUOXISO7816Commands::createDelegatedApplication(
    std::pair<ByteVector, ByteVector> damInfo, unsigned int aid, unsigned short DAMSlotNo,
    unsigned char DAMSlotVersion, unsigned short quotatLimit, DESFireKeySettings settings,
    unsigned char maxNbKeys, DESFireKeyType cryptoMethod, FidSupport fidSupported,
    unsigned short isoFID, ByteVector isoDFName, unsigned char numberKeySets,
    unsigned char maxKeySize, unsigned char actualkeySetVersion, unsigned char rollkeyno,
    bool specificCapabilityData, bool specificVCKeys)
{
    DESFireEV3ISO7816Commands::createDelegatedApplication(
        damInfo, aid, DAMSlotNo, DAMSlotVersion, quotatLimit, settings, maxNbKeys,
        cryptoMethod, fidSupported, isoFID, isoDFName, numberKeySets, maxKeySize,
        actualkeySetVersion, rollkeyno, specificCapabilityData, specificVCKeys);
}

std::pair<ByteVector, ByteVector> DUOXISO7816Commands::createDAMChallenge(
    std::shared_ptr<DESFireKey> DAMMACKey, std::shared_ptr<DESFireKey> DAMENCKey,
    std::shared_ptr<DESFireKey> DAMDefaultKey, unsigned int aid, unsigned short DAMSlotNo,
    unsigned char DAMSlotVersion, unsigned short quotatLimit, DESFireKeySettings settings,
    unsigned char maxNbKeys, DESFireKeyType cryptoMethod, FidSupport fidSupported,
    unsigned short isoFID, ByteVector isoDFName, unsigned char numberKeySets,
    unsigned char maxKeySize, unsigned char actualkeySetVersion, unsigned char rollkeyno,
    bool specificCapabilityData, bool specificVCKeys)
{
    return DESFireEV3ISO7816Commands::createDAMChallenge(
        DAMMACKey, DAMENCKey, DAMDefaultKey, aid, DAMSlotNo, DAMSlotVersion, quotatLimit,
        settings, maxNbKeys, cryptoMethod, fidSupported, isoFID, isoDFName, numberKeySets,
        maxKeySize, actualkeySetVersion, rollkeyno, specificCapabilityData,
        specificVCKeys);
}

void DUOXISO7816Commands::initializeKeySet(uint8_t keySetNo, DESFireKeyType keySetType)
{
    DESFireEV3ISO7816Commands::initializeKeySet(keySetNo, keySetType);
}

void DUOXISO7816Commands::rollKeySet(uint8_t keySetNo)
{
    DESFireEV3ISO7816Commands::rollKeySet(keySetNo);
}

void DUOXISO7816Commands::finalizeKeySet(uint8_t keySetNo, uint8_t keySetVersion)
{
    DESFireEV3ISO7816Commands::finalizeKeySet(keySetNo, keySetVersion);
}

void DUOXISO7816Commands::createStdDataFile(unsigned char fileno,
                                            EncryptionMode comSettings,
                                            const DESFireAccessRights &accessRights,
                                            unsigned int fileSize, unsigned short isoFID,
                                            bool multiAccessRights)
{
    DESFireEV3ISO7816Commands::createStdDataFile(fileno, comSettings, accessRights,
                                                 fileSize, isoFID, multiAccessRights);
}

void DUOXISO7816Commands::createBackupFile(unsigned char fileno,
                                           EncryptionMode comSettings,
                                           const DESFireAccessRights &accessRights,
                                           unsigned int fileSize, unsigned short isoFID,
                                           bool multiAccessRights)
{
    DESFireEV3ISO7816Commands::createBackupFile(fileno, comSettings, accessRights,
                                                fileSize, isoFID, multiAccessRights);
}

void DUOXISO7816Commands::createLinearRecordFile(
    unsigned char fileno, EncryptionMode comSettings,
    const DESFireAccessRights &accessRights, unsigned int fileSize,
    unsigned int maxNumberOfRecords, unsigned short isoFID, bool multiAccessRights)
{
    DESFireEV3ISO7816Commands::createLinearRecordFile(fileno, comSettings, accessRights,
                                                      fileSize, maxNumberOfRecords,
                                                      isoFID, multiAccessRights);
}

void DUOXISO7816Commands::createCyclicRecordFile(
    unsigned char fileno, EncryptionMode comSettings,
    const DESFireAccessRights &accessRights, unsigned int fileSize,
    unsigned int maxNumberOfRecords, unsigned short isoFID, bool multiAccessRights)
{
    DESFireEV3ISO7816Commands::createCyclicRecordFile(fileno, comSettings, accessRights,
                                                      fileSize, maxNumberOfRecords,
                                                      isoFID, multiAccessRights);
}

void DUOXISO7816Commands::createTransactionMACFile(
    unsigned char fileno, EncryptionMode comSettings,
    const DESFireAccessRights &accessRights, std::shared_ptr<DESFireKey> tmkey)
{
    DESFireEV3ISO7816Commands::createTransactionMACFile(fileno, comSettings, accessRights,
                                                        tmkey);
}

ByteVector DUOXISO7816Commands::getKeyVersion(uint8_t keysetno, uint8_t keyno)
{
    return DESFireEV3ISO7816Commands::getKeyVersion(keysetno, keyno);
}

void DUOXISO7816Commands::setConfiguration(bool formatCardEnabled, bool randomIdEnabled,
                                           bool PCMandatoryEnabled,
                                           bool AuthVCMandatoryEnabled)
{
    DESFireEV3ISO7816Commands::setConfiguration(
        formatCardEnabled, randomIdEnabled, PCMandatoryEnabled, AuthVCMandatoryEnabled);
}

void DUOXISO7816Commands::setConfiguration(uint8_t sak1, uint8_t sak2)
{
    DESFireEV3ISO7816Commands::setConfiguration(sak1, sak2);
}

void DUOXISO7816Commands::setConfiguration(bool D40SecureMessagingEnabled,
                                           bool EV1SecureMessagingEnabled,
                                           bool EV2ChainedWritingEnabled)
{
    DESFireEV3ISO7816Commands::setConfiguration(
        D40SecureMessagingEnabled, EV1SecureMessagingEnabled, EV2ChainedWritingEnabled);
}

void DUOXISO7816Commands::setConfigurationPDCap(uint8_t pdcap1_2, uint8_t pdcap2_5,
                                                uint8_t pdcap2_6)
{
    DESFireEV3ISO7816Commands::setConfigurationPDCap(pdcap1_2, pdcap2_5, pdcap2_6);
}

void DUOXISO7816Commands::setConfiguration(ByteVector DAMMAC, ByteVector ISODFNameOrVCIID)
{
    DESFireEV3ISO7816Commands::setConfiguration(DAMMAC, ISODFNameOrVCIID);
}

void DUOXISO7816Commands::changeFileSettings(
    unsigned char fileno, EncryptionMode comSettings,
    std::vector<DESFireAccessRights> accessRights)
{
    DESFireEV3ISO7816Commands::changeFileSettings(fileno, comSettings, accessRights);
}

void DUOXISO7816Commands::proximityCheck(std::shared_ptr<DESFireKey> key,
                                         uint8_t chunk_size)
{
    DESFireEV3ISO7816Commands::proximityCheck(key, chunk_size);
}

ByteVector DUOXISO7816Commands::commitTransaction(bool return_tmac)
{
    return DESFireEV3ISO7816Commands::commitTransaction(return_tmac);
}

ByteVector DUOXISO7816Commands::commitReaderID(ByteVector readerid)
{
    return DESFireEV3ISO7816Commands::commitReaderID(readerid);
}

void DUOXISO7816Commands::restoreTransfer(unsigned char target_fileno,
                                          unsigned char source_fileno)
{
    DESFireEV3ISO7816Commands::restoreTransfer(target_fileno, source_fileno);
}

ByteVector DUOXISO7816Commands::readSignature(unsigned char address)
{
    return DESFireEV3ISO7816Commands::readSignature(address);
}

bool DUOXISO7816Commands::performECCOriginalityCheck()
{
    return DESFireEV3ISO7816Commands::performECCOriginalityCheck();
}

// -------------------------------------------------------------------------
// DESFire EV3
// -------------------------------------------------------------------------
ByteVector DUOXISO7816Commands::getFileCounters(unsigned char fileno)
{
    return DESFireEV3ISO7816Commands::getFileCounters(fileno);
}

void DUOXISO7816Commands::createStdDataFile(unsigned char fileno, EncryptionMode comSettings,
                       const DESFireAccessRights &accessRights, unsigned int fileSize,
                       unsigned short isoFID, bool multiAccessRights,
                       bool sdmAndMirroring)
{
    DESFireEV3ISO7816Commands::createStdDataFile(fileno, comSettings, accessRights,
                                                 fileSize, isoFID, multiAccessRights,
                                                 sdmAndMirroring);
}

void DUOXISO7816Commands::changeFileSettings(unsigned char fileno, EncryptionMode comSettings,
                        std::vector<DESFireAccessRights> accessRights,
                        bool sdmAndMirroring, unsigned int tmcLimit, bool sdmVCUID,
                        bool sdmReadCtr, bool sdmReadCtrLimit, bool sdmEncFileData,
                        bool asciiEncoding, DESFireAccessRights sdmAccessRights,
                        unsigned int vcuidOffset, unsigned int sdmReadCtrOffset,
                        unsigned int piccDataOffset, unsigned int sdmMacInputOffset,
                        unsigned int sdmEncOffset, unsigned int sdmEncLength,
                        unsigned int sdmMacOffset,
                        unsigned int sdmReadCtrLimitValue)
{
    DESFireEV3ISO7816Commands::changeFileSettings(
        fileno, comSettings, accessRights, sdmAndMirroring, tmcLimit, sdmVCUID,
        sdmReadCtr, sdmReadCtrLimit, sdmEncFileData, asciiEncoding, sdmAccessRights,
        vcuidOffset, sdmReadCtrOffset, piccDataOffset, sdmMacInputOffset, sdmEncOffset,
        sdmEncLength, sdmMacOffset, sdmReadCtrLimitValue);
}

bool DUOXISO7816Commands::performAESOriginalityCheck()
{
    return DESFireEV3ISO7816Commands::performAESOriginalityCheck();
}

} // namespace logicalaccess