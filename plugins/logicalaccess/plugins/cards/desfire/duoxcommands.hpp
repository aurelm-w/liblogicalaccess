#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <logicalaccess/plugins/cards/desfire/desfireev3commands.hpp>

namespace logicalaccess
{
/**
 * \brief Curve identifiers supported by MIFARE DUOX asymmetric commands
 *
 * These values are the values transmitted to the card
 */
enum class DUOXCurveID : std::uint8_t
{
    NIST_P256        = 0x0C,
    BRAINPOOL_P256R1 = 0x0D
};

/**
 * \brief Options for the DUOX ManageKeyPair command
 *
 * ManageKeyPair (0x46) supports :
 *  - generating a new key pair,
 *  - importing a private key,
 *  - updating the metadata of an existing key pair
 */
enum class DUOXManageKeyPairOption : std::uint8_t
{
    GenerateKeyPair  = 0x00,
    ImportPrivateKey = 0x01,
    UpdateMetadata   = 0x02
};

/**
 * \brief DUOX secure messaging mode encoded in bits 4-5 of access conditions
 *
 * 00b = Plain
 * 01b = MAC
 * 10b = RFU
 * 11b = Full
 */
enum class DUOXCommunicationMode : std::uint8_t
{
    Plain = 0x00,
    MAC   = 0x01,
    Full  = 0x03
};

struct DUOXECCPrivateKeyMetadata
{
    std::uint8_t keyNo;
    DUOXCurveID curveId;
    std::uint16_t keyPolicy;
    std::uint8_t writeAccess;
    std::uint32_t keyUsageCtrLimit;
    std::uint32_t keyUsageCtr;

    DUOXECCPrivateKeyMetadata()
        : keyNo(0)
        , curveId(DUOXCurveID::NIST_P256)
        , keyPolicy(0)
        , writeAccess(0)
        , keyUsageCtrLimit(0)
        , keyUsageCtr(0)
    {
    }
};

struct DUOXCARootKeyMetadata
{
    std::uint8_t keyNo;
    DUOXCurveID curveId;
    std::uint16_t accessRights;
    std::uint8_t writeAccess;
    std::uint8_t readAccess;
    std::uint8_t crlFile;
    std::uint32_t crlFileAid;

    DUOXCARootKeyMetadata()
        : keyNo(0)
        , curveId(DUOXCurveID::NIST_P256)
        , accessRights(0)
        , writeAccess(0)
        , readAccess(0)
        , crlFile(0)
        , crlFileAid(0)
    {
    }
};

enum class DUOXGetKeySettingsResponseType : std::uint8_t
{
    KeySettings,
    ECCPrivateKeyMetadata,
    CARootKeyMetadata
};

struct DUOXKeySettings
{
    DUOXGetKeySettingsResponseType responseType;

    bool piccLevel;

    std::uint8_t keySettings;

    std::uint8_t maxNoOfKeys;
    std::uint8_t keyType;
    std::uint8_t numberOfKeys;

    bool hasApplicationKeySetSettings;
    std::uint8_t aksVersion;
    std::uint8_t noKeySets;
    std::uint8_t maxKeySize;
    std::uint8_t appKeySetSettings;

    std::vector<DUOXECCPrivateKeyMetadata> eccPrivateKeys;
    std::vector<DUOXCARootKeyMetadata> caRootKeys;

    DUOXKeySettings()
        : responseType(DUOXGetKeySettingsResponseType::KeySettings)
        , piccLevel(false)
        , keySettings(0)
        , maxNoOfKeys(0)
        , keyType(0)
        , numberOfKeys(0)
        , hasApplicationKeySetSettings(false)
        , aksVersion(0)
        , noKeySets(0)
        , maxKeySize(0)
        , appKeySetSettings(0)
    {
    }
};

/**
 * \brief Base commands class for DUOX cards
 *
 * DUOX is based on the DESFire EV3 command architecture. This class provides
 * the DUOX-specific command abstraction while reusing the DESFire EV3 command interface and behavior
 * 
 * Concrete DUOX command implementations, such as DUOXISO7816Commands, derive
 * from this class together with the appropriate transport-specific command implementation
 * 
 * This class is intended to serve as the common DUOX command abstraction
 */
class LLA_CARDS_DESFIRE_API DUOXCommands : public DESFireEV3Commands
{
  public:
    ~DUOXCommands() override;

    /**
     * \brief Manage an asymmetric private key entry
     *
     * This implements the DUOX ManageKeyPair command (0x46)
     *
     * Depending on \p option :
     *
     *  - GenerateKeyPair:
     *      Generates a key pair on the card. The generated public key is returned by the card
     *
     *  - ImportPrivateKey :
     *      Imports \p privateKey into the selected key slot
     *
     *  - UpdateMetadata :
     *      Updates the metadata of an existing key pair. The private key itself is not modified
     *
     * \param keyNo Key number to manage
     * \param option Operation to perform
     * \param curveId Curve used by the key pair
     * \param keyPolicy Two-byte DUOX key policy
     * \param writeAccess Write access condition
     * \param kucLimit Four-byte Key Usage Counter limit
     * \param privateKey Private key to import. It is only used with ImportPrivateKey
     *
     * \return The generated public key for GenerateKeyPair. For the other operations, the response is empty
     */
    virtual ByteVector manageKeyPair(std::uint8_t keyNo, DUOXManageKeyPairOption option,
                                     DUOXCurveID curveId, std::uint16_t keyPolicy,
                                     std::uint8_t writeAccess, std::uint32_t kucLimit,
                                     const ByteVector &privateKey = ByteVector(),
                                     DUOXCommunicationMode commMode = DUOXCommunicationMode::Full) = 0;

    //TODO Write comment later
    virtual void manageCARootKey(std::uint8_t keyNo, DUOXCurveID curveId,
                                 std::uint16_t accessRights, std::uint8_t writeAccess,
                                 std::uint8_t readAccess, std::uint8_t crlFile,
                                 std::uint32_t crlFileAid, const ByteVector &publicKey,
                                 const ByteVector &issuer,
                                 DUOXCommunicationMode commMode = DUOXCommunicationMode::Full) = 0;

    // TODO Write comment later
    virtual ByteVector exportKey(std::uint8_t keyNo, DUOXCommunicationMode commMode = DUOXCommunicationMode::Full) = 0;

    virtual void authenticateEV2NonFirst(uint8_t keyno, std::shared_ptr<DESFireKey> currentKey) = 0;

    virtual std::uint32_t freeMem() = 0;

    virtual DUOXKeySettings getKeySettings() = 0;
    virtual DUOXKeySettings getKeySettings(std::uint8_t option) = 0;

};

} // namespace logicalaccess