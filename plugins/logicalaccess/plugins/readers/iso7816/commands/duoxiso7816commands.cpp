#include <logicalaccess/plugins/readers/iso7816/commands/duoxiso7816commands.hpp>

#include <logicalaccess/plugins/cards/desfire/desfirechip.hpp>
#include <logicalaccess/plugins/cards/desfire/desfireev2crypto.hpp>

#include <logicalaccess/plugins/crypto/lla_random.hpp>
#include <logicalaccess/plugins/crypto/aes_helper.hpp>

namespace logicalaccess
{

namespace
{

    
constexpr std::uint8_t DUOX_INS_GET_KEY_SETTINGS   = 0x45;
constexpr std::uint8_t DUOX_INS_MANAGE_KEY_PAIR    = 0x46;
constexpr std::uint8_t DUOX_INS_EXPORT_KEY         = 0x47;
constexpr std::uint8_t DUOX_INS_MANAGE_CA_ROOT_KEY = 0x48;

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
                                              DUOXCurveID curveId, std::uint16_t keyPolicy,
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
    case DUOXCurveID::NIST_P256:
    case DUOXCurveID::BRAINPOOL_P256R1: break;
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

    //TODO For now any non-zero status is considered failure
    if (response.getSW2() != 0x00)
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
            "DUOX ManageKeyPair failed with status word " + byteToHex(response.getSW2()) + ".");

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
    std::uint8_t keyNo, DUOXCurveID curveId, std::uint16_t accessRights,
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
    case DUOXCurveID::NIST_P256:
    case DUOXCurveID::BRAINPOOL_P256R1: break;

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

    // For now any non-zero status is considered failure
    if (response.getSW2() != 0x00)
    {
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
            "DUOX ManageCARootKey failed with status word " + byteToHex(response.getSW2()) + ".");
    }

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

    // For now any non-zero status is considered failure
    if (response.getSW2() != 0x00)
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
            "DUOX ExportKey failed with status word " + byteToHex(response.getSW2()) + ".");

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

    if (data.size() != FREE_MEM_RESPONSE_SIZE)
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException, "DESFire FreeMem returned an invalid response length.");

    return static_cast<std::uint32_t>(data[0]) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           (static_cast<std::uint32_t>(data[2]) << 16U);
}

DUOXKeySettings DUOXISO7816Commands::getKeySettings()
{
    return getKeySettings(0x00);
}

DUOXKeySettings DUOXISO7816Commands::getKeySettings(std::uint8_t option)
{
    constexpr std::uint8_t OPTION_NONE            = 0x00;
    constexpr std::uint8_t OPTION_ECC_PRIVATE_KEY = 0x01;
    constexpr std::uint8_t OPTION_CA_ROOT_KEY     = 0x02;
    constexpr std::size_t ECC_METADATA_ENTRY_SIZE = 13;
    constexpr std::size_t CA_ROOT_METADATA_ENTRY_SIZE = 10;
    constexpr std::uint8_t MAX_METADATA_ENTRIES = 0x05;
    constexpr std::uint8_t KEY_TYPE_MASK = 0xC0;
    constexpr std::uint8_t KEY_COUNT_MASK = 0x3F;
    constexpr std::uint8_t KEY_TYPE_NA = 0x00;
    constexpr std::uint8_t KEY_TYPE_RESERVED = 0x40;
    constexpr std::uint8_t KEY_TYPE_AES128 = 0x80;
    constexpr std::uint8_t KEY_TYPE_AES256 = 0xC0;

    const auto chip = getDESFireChip();

    EXCEPTION_ASSERT_WITH_LOG(chip != nullptr,
        LibLogicalAccessException, "DUOX GetKeySettings requires an initialized DESFire chip.");

    const auto crypto = chip->getCrypto();

    EXCEPTION_ASSERT_WITH_LOG(crypto != nullptr,
        LibLogicalAccessException, "DUOX GetKeySettings requires an initialized DESFire crypto context.");

    const bool piccLevel = crypto->d_currentAid == DUOX_PICC_LEVEL_AID;

    EXCEPTION_ASSERT_WITH_LOG(
        option == OPTION_NONE || option == OPTION_ECC_PRIVATE_KEY || option == OPTION_CA_ROOT_KEY,
        LibLogicalAccessException,
        "Invalid DUOX GetKeySettings option : " + byteToHex(option) + ". Supported values are 0x00, 0x01 and 0x02.");

    ByteVector params;
    if (option != OPTION_NONE)
    {
        params.reserve(1);
        params.push_back(option);
    }

    const ByteVector command;

    const auto response = transmitDUOX(DUOX_INS_GET_KEY_SETTINGS, params, command, DUOXCommunicationMode::MAC);

    // For now any non-zero status is considered failure
    if (response.getSW2() != 0x00)
        THROW_EXCEPTION_WITH_LOG(LibLogicalAccessException,
            "DUOX GetKeySettings failed with status word " + byteToHex(response.getSW2()) + ".");

    const ByteVector &data = response.getData();

    DUOXKeySettings result;
    result.piccLevel = piccLevel;

    // ECC private key metadata
    if (option == OPTION_ECC_PRIVATE_KEY)
    {
        result.responseType = DUOXGetKeySettingsResponseType::ECCPrivateKeyMetadata;

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

            switch (static_cast<DUOXCurveID>(rawCurveId))
            {
            case DUOXCurveID::NIST_P256:
            case DUOXCurveID::BRAINPOOL_P256R1:
                entry.curveId = static_cast<DUOXCurveID>(rawCurveId);
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
    if (option == OPTION_CA_ROOT_KEY)
    {
        result.responseType = DUOXGetKeySettingsResponseType::CARootKeyMetadata;

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

            switch (static_cast<DUOXCurveID>(rawCurveId))
            {
            case DUOXCurveID::NIST_P256:
            case DUOXCurveID::BRAINPOOL_P256R1:
                entry.curveId = static_cast<DUOXCurveID>(rawCurveId);
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
    result.responseType = DUOXGetKeySettingsResponseType::KeySettings;

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

// ------------------
// DESFire EV2
// ------------------
void DUOXISO7816Commands::changeKeyEV2(uint8_t keyset, uint8_t keyno,
                                       std::shared_ptr<DESFireKey> key)
{
    DESFireEV3ISO7816Commands::changeKeyEV2(keyset, keyno, key);
}

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

// ------------------
// DESFire EV3
// ------------------
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