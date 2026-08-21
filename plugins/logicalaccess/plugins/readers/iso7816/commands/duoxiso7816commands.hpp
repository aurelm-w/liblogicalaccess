#pragma once

#include <logicalaccess/plugins/readers/iso7816/commands/desfireev3iso7816commands.hpp>
#include <logicalaccess/plugins/cards/desfire/duoxcommands.hpp>

namespace logicalaccess
{
/**
 * \brief ISO/IEC 7816 command implementation for DUOX cards
 *
 * DUOX commands are based on the DESFire EV3 command set and use the DESFire EV3 ISO/IEC 7816 transport implementation
 *
 * Multiple inheritance is intentional here :
 * - DESFireEV3ISO7816Commands provides the ISO/IEC 7816 implementation
 * - DUOXCommands provides the DUOX command interface
 *
 * The DESFire EV2/EV3 methods are explicitly forwarded to DESFireEV3ISO7816Commands
 * to resolve the duplicated DESFire command hierarchy introduced by the multiple inheritance
 */
#define CMD_DUOXISO7816 "DUOXISO7816"

class LLA_READERS_ISO7816_API DUOXISO7816Commands : public DESFireEV3ISO7816Commands,
                                                    public DUOXCommands
{
  public:
    /**
     * \brief Constructs DUOX ISO/IEC 7816 commands
     *
     * Initializes the underlying DESFire EV3 ISO/IEC 7816 implementation with the DUOX command type
     */
    DUOXISO7816Commands();

    /**
     * \brief Destructor
     */
    ~DUOXISO7816Commands() override = default;

    /**
     * \brief Get the DUOX chip associated with these commands
     *
     * \return The associated DUOX chip
     */
    std::shared_ptr<Chip> getChip() const override;

    /**
     * \brief Get the reader/card adapter used by these commands
     *
     * \return The reader/card adapter
     */
    std::shared_ptr<ReaderCardAdapter> getReaderCardAdapter() const override;

    /**
     * \brief Manage a DUOX asymmetric private key entry.
     *
     * Implements the DUOX ManageKeyPair command (0x46).
     */
    ByteVector manageKeyPair(std::uint8_t keyNo, DUOXManageKeyPairOption option,
                             DUOXCurveID curveId, std::uint16_t keyPolicy,
                             std::uint8_t writeAccess, std::uint32_t kucLimit,
                             const ByteVector &privateKey = ByteVector(),
                             DUOXCommunicationMode commMode = DUOXCommunicationMode::Full) override;

    void manageCARootKey(std::uint8_t keyNo, DUOXCurveID curveId,
                         std::uint16_t accessRights, std::uint8_t writeAccess,
                         std::uint8_t readAccess, std::uint8_t crlFile,
                         std::uint32_t crlFileAid, const ByteVector &publicKey,
                         const ByteVector &issuer, DUOXCommunicationMode commMode = DUOXCommunicationMode::Full) override;

    ByteVector exportKey(std::uint8_t keyNo, DUOXCommunicationMode commMode = DUOXCommunicationMode::Full) override;

    void authenticateEV2NonFirst(uint8_t keyno, std::shared_ptr<DESFireKey> currentKey) override;

    std::uint32_t freeMem() override;

    DUOXKeySettings getKeySettings() override;
    DUOXKeySettings getKeySettings(std::uint8_t option) override;

    /*
     * DESFire EV2 command interface.
     *
     * Explicit forwarding is required because DUOXCommands and
     * DESFireEV3ISO7816Commands both inherit from the DESFire command hierarchy
     * The ISO/IEC 7816 implementation remains the actual implementation
     */
    void changeKeyEV2(uint8_t keyset, uint8_t keyno,
                      std::shared_ptr<DESFireKey> key) override;

    void authenticateEV2First(uint8_t keyno, std::shared_ptr<DESFireKey> key) override;

    void sam_authenticateEV2First(uint8_t keyno,
                                  std::shared_ptr<DESFireKey> key) override;

    void createApplication(
        unsigned int aid, DESFireKeySettings settings, unsigned char maxNbKeys,
        DESFireKeyType cryptoMethod, FidSupport fidSupported = FIDS_NO_ISO_FID,
        unsigned short isoFID = 0x00, ByteVector isoDFName = ByteVector(),
        unsigned char numberKeySets = 0, unsigned char maxKeySize = 0,
        unsigned char actualkeySetVersion = 0, unsigned char rollkeyno = 0,
        bool specificCapabilityData = false, bool specificVCKeys = false) override;

    void createDelegatedApplication(
        std::pair<ByteVector, ByteVector> damInfo, unsigned int aid,
        unsigned short DAMSlotNo, unsigned char DAMSlotVersion,
        unsigned short quotatLimit, DESFireKeySettings settings, unsigned char maxNbKeys,
        DESFireKeyType cryptoMethod, FidSupport fidSupported = FIDS_NO_ISO_FID,
        unsigned short isoFID = 0x00, ByteVector isoDFName = ByteVector(),
        unsigned char numberKeySets = 0, unsigned char maxKeySize = 0,
        unsigned char actualkeySetVersion = 0, unsigned char rollkeyno = 0,
        bool specificCapabilityData = false, bool specificVCKeys = false) override;

    std::pair<ByteVector, ByteVector> createDAMChallenge(
        std::shared_ptr<DESFireKey> DAMMACKey, std::shared_ptr<DESFireKey> DAMENCKey,
        std::shared_ptr<DESFireKey> DAMDefaultKey, unsigned int aid,
        unsigned short DAMSlotNo, unsigned char DAMSlotVersion,
        unsigned short quotatLimit, DESFireKeySettings settings, unsigned char maxNbKeys,
        DESFireKeyType cryptoMethod, FidSupport fidSupported = FIDS_NO_ISO_FID,
        unsigned short isoFID = 0x00, ByteVector isoDFName = ByteVector(),
        unsigned char numberKeySets = 0, unsigned char maxKeySize = 0,
        unsigned char actualkeySetVersion = 0, unsigned char rollkeyno = 0,
        bool specificCapabilityData = false, bool specificVCKeys = false) override;

    void initializeKeySet(uint8_t keySetNo, DESFireKeyType keySetType) override;

    void rollKeySet(uint8_t keySetNo) override;

    void finalizeKeySet(uint8_t keySetNo, uint8_t keySetVersion) override;

    void createStdDataFile(unsigned char fileno, EncryptionMode comSettings,
                           const DESFireAccessRights &accessRights, unsigned int fileSize,
                           unsigned short isoFID, bool multiAccessRights) override;

    void createBackupFile(unsigned char fileno, EncryptionMode comSettings,
                          const DESFireAccessRights &accessRights, unsigned int fileSize,
                          unsigned short isoFID, bool multiAccessRights) override;

    void createLinearRecordFile(unsigned char fileno, EncryptionMode comSettings,
                                const DESFireAccessRights &accessRights,
                                unsigned int fileSize, unsigned int maxNumberOfRecords,
                                unsigned short isoFID, bool multiAccessRights) override;

    void createCyclicRecordFile(unsigned char fileno, EncryptionMode comSettings,
                                const DESFireAccessRights &accessRights,
                                unsigned int fileSize, unsigned int maxNumberOfRecords,
                                unsigned short isoFID, bool multiAccessRights) override;

    void createTransactionMACFile(unsigned char fileno, EncryptionMode comSettings,
                                  const DESFireAccessRights &accessRights,
                                  std::shared_ptr<DESFireKey> tmkey) override;

    ByteVector getKeyVersion(uint8_t keysetno, uint8_t keyno) override;

    void setConfiguration(bool formatCardEnabled, bool randomIdEnabled,
                          bool PCMandatoryEnabled, bool AuthVCMandatoryEnabled) override;

    void setConfiguration(uint8_t sak1, uint8_t sak2) override;

    void setConfiguration(bool D40SecureMessagingEnabled, bool EV1SecureMessagingEnabled,
                          bool EV2ChainedWritingEnabled) override;

    void setConfigurationPDCap(uint8_t pdcap1_2, uint8_t pdcap2_5,
                               uint8_t pdcap2_6) override;

    void setConfiguration(ByteVector DAMMAC, ByteVector ISODFNameOrVCIID) override;

    void changeFileSettings(unsigned char fileno, EncryptionMode comSettings,
                            std::vector<DESFireAccessRights> accessRights) override;

    void proximityCheck(std::shared_ptr<DESFireKey> key, uint8_t chunk_size) override;

    ByteVector commitTransaction(bool return_tmac) override;

    ByteVector commitReaderID(ByteVector readerid) override;

    void restoreTransfer(unsigned char target_fileno,
                         unsigned char source_fileno) override;

    ByteVector readSignature(unsigned char address = 0x00) override;

    bool performECCOriginalityCheck() override;

    /*
     * DESFire EV3 command interface.
     *
     * Explicitly forwarded to the ISO/IEC 7816 implementation to resolve the duplicated DESFireEV3Commands base
     */
    ByteVector getFileCounters(unsigned char fileno) override;

    void createStdDataFile(unsigned char fileno, EncryptionMode comSettings,
                                   const DESFireAccessRights &accessRights,
                                   unsigned int fileSize,
                                   unsigned short isoFID,
                                   bool multiAccessRights, bool sdmAndMirroring) override;

    void changeFileSettings(unsigned char fileno, EncryptionMode comSettings,
                                    std::vector<DESFireAccessRights> accessRights,
                                    bool sdmAndMirroring,
                                    unsigned int tmcLimit,
                                    bool sdmVCUID,
                                    bool sdmReadCtr,
                                    bool sdmReadCtrLimit,
                                    bool sdmEncFileData,
                                    bool asciiEncoding,
                                    DESFireAccessRights sdmAccessRights,
                                    unsigned int vcuidOffset,
                                    unsigned int sdmReadCtrOffset,
                                    unsigned int piccDataOffset,
                                    unsigned int sdmMacInputOffset,
                                    unsigned int sdmEncOffset,
                                    unsigned int sdmEncLength,
                                    unsigned int sdmMacOffset,
                                    unsigned int sdmReadCtrLimitValue) override;

    bool performAESOriginalityCheck() override;

    protected:
    ISO7816Response transmitDUOX(std::uint8_t cmd, const ByteVector &params, const ByteVector &data,
                 DUOXCommunicationMode commMode = DUOXCommunicationMode::Full);
};

} // namespace logicalaccess