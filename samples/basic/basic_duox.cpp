#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <logicalaccess/bufferhelper.hpp>
#include <logicalaccess/dynlibrary/librarymanager.hpp>
#include <logicalaccess/readerproviders/readerconfiguration.hpp>

#include <logicalaccess/plugins/cards/desfire/duoxcommands.hpp>
#include <logicalaccess/plugins/readers/iso7816/commands/duoxiso7816commands.hpp>

#include <logicalaccess/plugins/cards/desfire/desfirecommands.hpp>
#include <logicalaccess/plugins/cards/desfire/desfirechip.hpp>

/*
 * This executable serves both as a functional test suite and as a usage example for DUOX commands
 * The operations exercised here are representative of real application workflows
 * while the test-specific safety restrictions keep all destructive operations isolated to the dedicated test application
 */

namespace
{
    enum class DUOXCardPreparationMode
    {
        EraseCard,
        DeleteTestApplication
    };

    constexpr DUOXCardPreparationMode CARD_PREPARATION_MODE = DUOXCardPreparationMode::EraseCard;

    constexpr char READER_PROVIDER[] = "PCSC";

    // Select the physical reader by its stable PC/SC name instead of enumeration index
    // This prevents reader ordering changes from selecting the wrong device
    constexpr char DESFIRE_READER_NAME[] = "HID Global OMNIKEY 5422CL Smartcard Reader 0";

    constexpr unsigned int CARD_INSERTION_TIMEOUT_MS = 15000;

    // =========================== DUOX test configuration ===========================
    constexpr std::uint32_t PICC_LEVEL_AID = 0x000000;

    // Dedicated test application. This application must never be provisioned for any other purpose
    constexpr std::uint32_t DUOX_TEST_APPLICATION_AID = 0x123456;

    // Authenticate using PICC master key number 0
    constexpr std::uint8_t PICC_MASTER_KEY_NO = 0;
    // Authenticate using key number 0 of DUOX_TEST_APPLICATION_AID
    constexpr std::uint8_t TEST_APPLICATION_AUTH_KEY_NO = 0;

    // ECC private key slot inside the dedicated test application
    constexpr std::uint8_t TEST_ECC_KEY_SLOT_P256      = 0; // DUOX ECC key slot 0
    constexpr std::uint8_t TEST_ECC_KEY_SLOT_BRAINPOOL = 1;
    constexpr std::uint8_t TEST_ECC_KEY_SLOT_IMPORT    = 2;

    // No key-usage limit
    constexpr std::uint32_t DUOX_TEST_KUC_LIMIT = 0;

    // No ECC operation enabled
    constexpr std::uint16_t DUOX_TEST_KEY_POLICY = 0x0000;

    // WriteAccess is discussed below. We should use a value which permits ManageKeyPair
    // through the authenticated application master key without making the ECC key permanently unmodifiable
    constexpr auto DUOX_COMM_MODE = logicalaccess::DUOXCommunicationMode::Full;
    constexpr std::uint8_t DUOX_COMM_MODE_BITS = static_cast<std::uint8_t>(DUOX_COMM_MODE) << 4;
    constexpr std::uint8_t DUOX_TEST_WRITE_AR = 0x0E; // free access
    constexpr std::uint8_t DUOX_TEST_WRITE_ACCESS = DUOX_TEST_WRITE_AR | DUOX_COMM_MODE_BITS; // free access

    // CA Root Key slot inside the dedicated test application
    constexpr std::uint8_t TEST_CA_ROOT_KEY_SLOT = 0;

    // No CA Root Key access rights enabled by default
    constexpr std::uint16_t DUOX_TEST_CA_ACCESS_RIGHTS = 0x0000;

    // CA Root Key WriteAccess
    constexpr std::uint8_t DUOX_TEST_CA_WRITE_ACCESS = DUOX_TEST_WRITE_AR | DUOX_COMM_MODE_BITS;

    // CA Root Key ReadAccess
    constexpr std::uint8_t DUOX_TEST_CA_READ_ACCESS = DUOX_TEST_WRITE_AR | DUOX_COMM_MODE_BITS;

    // Certificate revocation disabled
    constexpr std::uint8_t DUOX_TEST_CA_CRL_FILE      = 0x00;
    constexpr std::uint32_t DUOX_TEST_CA_CRL_FILE_AID = 0x000000;

    // A recognizable test issuer
    const ByteVector DUOX_TEST_CA_ISSUER{'D', 'U', 'O', 'X', '-', 'T', 'E', 'S', 'T'};

    // GetKeySettings
    constexpr std::uint8_t GET_KEY_SETTINGS_OPTION_NONE            = 0x00;
    constexpr std::uint8_t GET_KEY_SETTINGS_OPTION_ECC_PRIVATE_KEY = 0x01;
    constexpr std::uint8_t GET_KEY_SETTINGS_OPTION_CA_ROOT_KEY     = 0x02;

    constexpr std::size_t EXPECTED_P256_PUBLIC_KEY_SIZE   = 65U;
    constexpr std::size_t EXPECTED_ECC_METADATA_COUNT     = 4U;
    constexpr std::size_t EXPECTED_CA_ROOT_METADATA_COUNT = 1U;

    // GetKeySettings MaxNoOfKeys byte :
    // bits 7..6 = AES key type
    // 10b = AES-128 (0x80)
    // 11b = AES-256 (0xC0)
    // TODO Change this considering it's with the GetKeySettings command implementation
    constexpr std::uint8_t KEY_TYPE_AES128 = 0x80;
    constexpr std::uint8_t KEY_TYPE_AES256 = 0xC0;

    // ======================================================

std::shared_ptr<logicalaccess::DESFireKey> createTestPiccMasterKey()
    {
        auto key = std::make_shared<logicalaccess::DESFireKey>();

        key->setKeyType(logicalaccess::DF_KEY_AES);
        // Test PICC Master Key
        // This must match the actual AES PICC Master Key provisioned on the test card
        key->fromString("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

        return key;
    }

std::shared_ptr<logicalaccess::ReaderUnit> findReaderByName(
    const std::shared_ptr<logicalaccess::ReaderProvider>& provider,
    const std::string& readerName)
{
    if (!provider)
        throw std::runtime_error("PCSC reader provider is null.");

    const auto readers = provider->getReaderList();

    if (readers.empty())
        throw std::runtime_error("No PCSC readers detected.");

    for (const auto& reader : readers)
    {
        if (reader && reader->getName() == readerName)
            return reader;
    }

    std::string availableReaders;

    for (const auto& reader : readers)
    {
        if (!reader)
            continue;
        if (!availableReaders.empty())
            availableReaders += "\n";
        availableReaders += "  - ";
        availableReaders += reader->getName();
    }

    throw std::runtime_error("Required PCSC reader was not found :\n  Expected : " +
                             readerName + "\nAvailable readers :\n" + availableReaders);
}

std::shared_ptr<logicalaccess::ReaderConfiguration> createReaderConfiguration()
{
    auto configuration = std::make_shared<logicalaccess::ReaderConfiguration>();
    auto* libraryManager = logicalaccess::LibraryManager::getInstance();

    if (!libraryManager)
        throw std::runtime_error("LogicalAccess LibraryManager is unavailable.");

    auto provider = libraryManager->getReaderProvider(READER_PROVIDER);

    if (!provider)
        throw std::runtime_error("Unable to load the PCSC reader provider.");

    const auto reader = findReaderByName(provider, DESFIRE_READER_NAME);
    configuration->setReaderProvider(provider);
    configuration->setReaderUnit(reader);

    return configuration;
}

std::shared_ptr<logicalaccess::Chip> waitForCard(
    const std::shared_ptr<logicalaccess::ReaderConfiguration>& configuration)
{
    if (!configuration)
        throw std::runtime_error("Reader configuration is null.");

    const auto reader = configuration->getReaderUnit();

    if (!reader)
        throw std::runtime_error("Configured reader is null.");

    std::cout << "[INFO] Reader : " << reader->getName() << '\n';
    std::cout << "[INFO] Waiting " << CARD_INSERTION_TIMEOUT_MS / 1000 << " seconds for card insertion..." << std::endl;

    // The timestamp is not particularly useful by itself but it provides a consistent reference point
    // when comparing different test executions
    const auto startTime = std::time(nullptr);

    if (startTime != static_cast<std::time_t>(-1))
        std::cout << "[INFO] Time start : " << std::ctime(&startTime);

    // Establish the connection with the physical reader
    reader->connectToReader();

    // LogicalAccess is allowed to identify the inserted card normally
    if (!reader->waitInsertion(CARD_INSERTION_TIMEOUT_MS))
    {
        reader->disconnect();
        throw std::runtime_error("No card was inserted within the timeout.");
    }

    if (!reader->connect())
    {
        reader->disconnect();
        throw std::runtime_error("A card was detected, but communication with the card could not be established.");
    }

    const auto chip = reader->getSingleChip();

    if (!chip)
    {
        reader->disconnect();
        throw std::runtime_error("The reader connected successfully, but LogicalAccess could not identify the card.");
    }

    return chip;
}

bool isDUOXCard(const std::shared_ptr<logicalaccess::Chip> &chip)
{
    if (!chip)
        return false;

    return chip->getCardType() == "DUOX";
}

/*
 * Guardrail against accidentally treating the PICC level as the dedicated test application
 * This does not verify the currently selected AID :
 * callers must validate the card context before performing application-level operations
 */
void assertTestAidIsNotPiccLevel()
{
    if (DUOX_TEST_APPLICATION_AID == PICC_LEVEL_AID)
        throw std::runtime_error("Safety check failed : DUOX test must never run at PICC level.");
}

/*
 * The test suite permits destructive operations ONLY on DUOX_TEST_APPLICATION_AID
 *
 * No other application and no PICC data are intentionally modified,
 * except the PICC-level authentication required to create/delete the dedicated test application
 */
void printTestSafetyPolicy()
{
    std::cout << "\n========== DUOX TEST SAFETY POLICY ==========\n";

    std::cout << "[SAFETY] Test AID : 0x" << std::uppercase << std::hex << std::setw(6)
              << std::setfill('0') << DUOX_TEST_APPLICATION_AID << std::dec << '\n';

    std::cout << "[SAFETY] PICC-level operations   : RESTRICTED TO TEST LIFECYCLE\n"
              << "[SAFETY] PICC Master Key         : AUTHENTICATION ONLY\n"
              << "[SAFETY] Application creation    : ONLY 0x" << std::uppercase
              << std::hex << std::setw(6) << std::setfill('0')
              << DUOX_TEST_APPLICATION_AID << std::dec << '\n'
              << "[SAFETY] Application deletion    : ONLY 0x" << std::uppercase
              << std::hex << std::setw(6) << std::setfill('0')
              << DUOX_TEST_APPLICATION_AID << std::dec << '\n'
              << "[SAFETY] ChangeKey               : DISABLED\n"
              << "[SAFETY] SetConfiguration        : DISABLED\n"
              << "[SAFETY] Key-set operations      : DISABLED\n"
              << "[SAFETY] Other application AIDs  : NEVER TOUCHED\n"
              << "[SAFETY] ManageKeyPair           : ALLOWED ONLY after explicit test-AID authentication\n";

    std::cout << "==============================================\n";
}

std::vector<unsigned int> listApplications(const std::shared_ptr<logicalaccess::DESFireCommands>& commands)
{
    if (!commands)
        throw std::runtime_error("DESFire command interface is null.");

    const auto applications = commands->getApplicationIDs();

    std::cout << "\n========================================\n";
    std::cout << " Applications currently on card\n";
    std::cout << "========================================\n";

    if (applications.empty())
    {
        std::cout << "[INFO] No applications reported.\n";
    }
    else
    {
        for (const auto aid : applications)
        {
            std::cout << "  - AID 0x" << std::uppercase << std::hex << std::setw(6)
                      << std::setfill('0') << aid << std::dec << '\n';
        }
    }
    std::cout << "========================================\n";
    return applications;
}

bool applicationExists(const std::vector<unsigned int> &applications, unsigned int aid)
{
    return std::find(applications.begin(), applications.end(), aid) != applications.end();
}

void deleteTestApplication(const std::shared_ptr<logicalaccess::DESFireCommands> &desfireCommands,
    const std::shared_ptr<logicalaccess::DUOXCommands>& duoxCommands)
{
    if (!desfireCommands)
        throw std::runtime_error("DESFire commands are null.");

    if (!duoxCommands)
        throw std::runtime_error("DUOX commands are null.");

    std::cout << "[INFO] Selecting PICC level for test-application cleanup...\n";

    desfireCommands->selectApplication(PICC_LEVEL_AID);

    std::cout << "[INFO] Authenticating PICC Master Key...\n";

    const auto piccKey = createTestPiccMasterKey();
    duoxCommands->authenticateEV2First(PICC_MASTER_KEY_NO, piccKey);

    std::cout << "[INFO] Deleting ONLY test application 0x" << std::uppercase << std::hex
              << std::setw(6) << std::setfill('0') << DUOX_TEST_APPLICATION_AID
              << std::dec << "...\n";

    desfireCommands->deleteApplication(DUOX_TEST_APPLICATION_AID);

    std::cout << "[PASS] Test application deleted.\n";
}

class DUOXTestApplicationGuard
{
  public:
    DUOXTestApplicationGuard(
        const std::shared_ptr<logicalaccess::DESFireCommands> &desfireCommands,
        const std::shared_ptr<logicalaccess::DUOXCommands> &duoxCommands,
        std::uint32_t aid)
        : desfireCommands_(desfireCommands)
        , duoxCommands_(duoxCommands)
        , aid_(aid)
    {
        if (!desfireCommands_)
            throw std::runtime_error(
                "DUOX test application guard received null DESFire commands.");

        if (!duoxCommands_)
            throw std::runtime_error(
                "DUOX test application guard received null DUOX commands.");

        if (aid_ == PICC_LEVEL_AID)
            throw std::runtime_error(
                "DUOX test application guard cannot target PICC level.");

         // The guard is constructed only after CreateApplication succeeds
         // From this point on cleanup owns responsibility for the test application
        created_ = true;
    }

    ~DUOXTestApplicationGuard()
    {
        if (!created_)
            return;

        try
        {
            cleanup();
        }
        catch (const std::exception &exception)
        {
            std::cerr << "[WARNING] Failed to delete DUOX test application 0x"
                      << std::uppercase << std::hex << std::setw(6) << std::setfill('0')
                      << aid_ << std::dec
                      << " during automatic cleanup : " << exception.what()
                      << "\n[WARNING] Manual cleanup may be required.\n";
        }
        catch (...)
        {
            std::cerr << "[WARNING] Failed to delete DUOX test application 0x"
                      << std::uppercase << std::hex << std::setw(6) << std::setfill('0')
                      << aid_ << std::dec
                      << " during automatic cleanup due to an unknown error.\n"
                      << "[WARNING] Manual cleanup may be required.\n";
        }
    }

    DUOXTestApplicationGuard(const DUOXTestApplicationGuard &)            = delete;
    DUOXTestApplicationGuard &operator=(const DUOXTestApplicationGuard &) = delete;

    DUOXTestApplicationGuard(DUOXTestApplicationGuard &&)            = delete;
    DUOXTestApplicationGuard &operator=(DUOXTestApplicationGuard &&) = delete;

    void cleanup()
    {
        if (!created_)
            return;

        assertTestAidIsNotPiccLevel();

        std::cout << "[CLEANUP] Selecting PICC level...\n";

        desfireCommands_->selectApplication(PICC_LEVEL_AID);

        std::cout << "[CLEANUP] Authenticating PICC master key...\n";

        const auto piccKey = createTestPiccMasterKey();

        duoxCommands_->authenticateEV2First(PICC_MASTER_KEY_NO, piccKey);

        const auto applications = desfireCommands_->getApplicationIDs();

        if (!applicationExists(applications, aid_))
        {
            created_ = false;

            std::cout << "[CLEANUP] Test application no longer exists.\n";

            return;
        }

        std::cout << "[CLEANUP] Deleting ONLY DUOX test application 0x" << std::uppercase
                  << std::hex << std::setw(6) << std::setfill('0') << aid_ << std::dec
                  << "...\n";

        desfireCommands_->deleteApplication(aid_);

        const auto applicationsAfterDeletion = desfireCommands_->getApplicationIDs();

        if (applicationExists(applicationsAfterDeletion, aid_))
        {
            throw std::runtime_error(
                "DUOX test application still exists after deletion.");
        }

        created_ = false;

        std::cout << "[CLEANUP] DUOX test application deleted.\n";
    }

  private:
    std::shared_ptr<logicalaccess::DESFireCommands> desfireCommands_;
    std::shared_ptr<logicalaccess::DUOXCommands> duoxCommands_;
    std::uint32_t aid_;
    bool created_ = false;
};

// Full erase is used by the default preparation mode because deleting the test application alone does not provide
// the same clean NV-memory baseline required by these memory lifecycle tests
void eraseTestCard(const std::shared_ptr<logicalaccess::DESFireCommands> &desfireCommands,
                   const std::shared_ptr<logicalaccess::DUOXCommands> &duoxCommands)
{
    if (!desfireCommands)
        throw std::runtime_error("DESFire commands are null.");

    if (!duoxCommands)
        throw std::runtime_error("DUOX commands are null.");

    assertTestAidIsNotPiccLevel();

    std::cout << "\n========================================\n"
              << " DUOX TEST CARD ERASE\n"
              << "========================================\n";

    std::cout << "[WARNING] This operation will permanently remove ALL "
                 "applications and files from the card.\n";

    std::cout << "[WARNING] The PICC Master Key will NOT be modified.\n";

    std::cout << "[INFO] Selecting PICC level...\n";

    desfireCommands->selectApplication(PICC_LEVEL_AID);

    std::cout << "[INFO] Authenticating PICC Master Key...\n";

    const auto piccKey = createTestPiccMasterKey();

    duoxCommands->authenticateEV2First(PICC_MASTER_KEY_NO, piccKey);

    std::cout << "[INFO] Erasing / formatting PICC...\n";

    desfireCommands->erase();

    // IMPORTANT :
    // Erase is a PICC-level destructive operation !
    // Do not rely on the previous authentication/session remaining valid after the erase

    std::cout << "[PASS] PICC erased successfully.\n";
    std::cout << "[INFO] All applications and files were removed.\n";
    std::cout << "[INFO] NV memory is now available for reuse.\n";

    const auto applications = desfireCommands->getApplicationIDs();

    if (!applications.empty())
    {
        throw std::runtime_error(
            "PICC erase completed but applications are still reported.");
    }

    std::cout << "[PASS] Application list is empty after erase.\n";

    std::cout << "========================================\n";
}

void prepareDUOXTestCard(
    const std::shared_ptr<logicalaccess::DESFireCommands> &desfireCommands,
    const std::shared_ptr<logicalaccess::DUOXCommands> &duoxCommands)
{
    if (!desfireCommands)
        throw std::runtime_error("DESFire commands are null.");

    if (!duoxCommands)
        throw std::runtime_error("DUOX commands are null.");

    std::cout << "\n========================================\n";
    std::cout << " DUOX CARD PREPARATION\n";
    std::cout << "========================================\n";

    // 1 - Show current applications before test preparation
    const auto applications = listApplications(desfireCommands);

    // 2 - Format the card to release all previously allocated NV memory
    // OR
    // If dedicated test application already exists, deletes it
    if (CARD_PREPARATION_MODE == DUOXCardPreparationMode::EraseCard)
    {
        std::cout << "[INFO] Preparation mode : FULL PICC ERASE\n";

        eraseTestCard(desfireCommands, duoxCommands);
    }
    else
    {
        std::cout << "[INFO] Preparation mode : DELETE TEST APPLICATION ONLY\n";

        if (applicationExists(applications, DUOX_TEST_APPLICATION_AID))
        {
            deleteTestApplication(desfireCommands, duoxCommands);
        }
        else
        {
            std::cout << "[INFO] Test application does not exist.\n";
        }
    }

    const auto applicationsAfterPreparation = listApplications(desfireCommands);
    if (applicationsAfterPreparation.empty())
        std::cout << "[PASS] No applications remain after card preparation.\n";

    std::cout << "========================================\n";
}

}

void runDUOXManageKeyPairTests(const std::shared_ptr<logicalaccess::Chip> &chip)
{
    if (!chip)
        throw std::runtime_error("DUOX chip is null.");

    // TODO refactor as 1 struct of 2 pointers instead of having 2 direct pointers
    // Don't do it now, it'll be part of another refactor
    auto desfireCommands = std::dynamic_pointer_cast<logicalaccess::DESFireCommands>(chip->getCommands());

    if (!desfireCommands)
        throw std::runtime_error("DUOX card does not expose DESFireCommands.");

    auto duoxCommands = std::dynamic_pointer_cast<logicalaccess::DUOXCommands>(chip->getCommands());

    if (!duoxCommands)
        throw std::runtime_error("DUOX card does not expose DUOXCommands.");

    assertTestAidIsNotPiccLevel();

    std::cout << "\n========================================\n";
    std::cout << " DUOX ManageKeyPair tests\n";
    std::cout << "========================================\n";

    // Safety configuration (must exist for each set of test)
    printTestSafetyPolicy();

    // 1 - Prepare the card
    prepareDUOXTestCard(desfireCommands, duoxCommands);

    // -------------------------------------------------------------------------
    // TEST 1 - FreeMem immediately after card preparation
    // -------------------------------------------------------------------------
    std::uint32_t freeMemoryBeforeTestApplication = 0;
    {
         std::cout << "\n[TEST 1] Query DUOX free NV memory before test application "
                     "creation...\n";

        /*
         * FreeMem is a PICC-level command
         *
         * The card has just been prepared and no DUOX test application has been created yet
         * This gives us a useful baseline for the memory lifecycle tests
         */
        freeMemoryBeforeTestApplication = duoxCommands->freeMem();
         std::cout << "[PASS] FreeMem succeeded.\n";
         std::cout << "[INFO] Free NV memory before test application : "
                   << freeMemoryBeforeTestApplication << " bytes\n";
    }

    // 2 - Create only the dedicated test application
    std::cout << "\n[INFO] Creating dedicated DUOX test application 0x" << std::uppercase
              << std::hex << std::setw(6) << std::setfill('0')
              << DUOX_TEST_APPLICATION_AID << std::dec << "...\n";

    // PICC-level operation : required for CreateApplication/DeleteApplication
    desfireCommands->selectApplication(PICC_LEVEL_AID);

    const auto piccKey = createTestPiccMasterKey();

    // PICC authentication is required to create an application
    // Re-select and re-authenticate after erase before creating the test application
    duoxCommands->authenticateEV2First(PICC_MASTER_KEY_NO, piccKey);

    duoxCommands->createApplication(DUOX_TEST_APPLICATION_AID,
                                       logicalaccess::KS_DEFAULT, 2,
                                       logicalaccess::DF_KEY_AES);
    DUOXTestApplicationGuard cleanup(desfireCommands, duoxCommands, DUOX_TEST_APPLICATION_AID);

    std::cout << "[PASS] Dedicated DUOX test application created.\n";

    // 3 - Select ONLY the dedicated application
    std::cout << "[INFO] Selecting test application 0x" << std::uppercase << std::hex
              << std::setw(6) << std::setfill('0') << DUOX_TEST_APPLICATION_AID
              << std::dec << "...\n";

    desfireCommands->selectApplication(DUOX_TEST_APPLICATION_AID);

    // 4 - Verify the actual LogicalAccess application context
    const auto desfireChip = std::dynamic_pointer_cast<logicalaccess::DESFireChip>(chip);

    if (!desfireChip)
        throw std::runtime_error("DUOX card is not accessible as DESFireChip.");

    const auto crypto = desfireChip->getCrypto();

    if (!crypto)
        throw std::runtime_error("DESFire crypto context is not initialized.");

    std::cout << "[INFO] Current AID after selection : 0x" << std::uppercase << std::hex
              << std::setw(6) << std::setfill('0') << crypto->d_currentAid << std::dec
              << '\n';

    if (crypto->d_currentAid != DUOX_TEST_APPLICATION_AID)
        throw std::runtime_error("SAFETY FAILURE : LogicalAccess selected an unexpected AID.");

    std::cout << "[PASS] Correct DUOX test application selected.\n";

    // 5 - Authenticate ONLY to the test application
    std::cout << "[INFO] Authenticating to the dedicated DUOX application...\n";

    auto testAuthKey = std::make_shared<logicalaccess::DESFireKey>();

    testAuthKey->setKeyType(logicalaccess::DF_KEY_AES);

    // Actual key provisioned in the dedicated test application (only 0 by default)
    testAuthKey->fromString("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");

    duoxCommands->authenticateEV2First(TEST_APPLICATION_AUTH_KEY_NO, testAuthKey);

    std::cout << "[PASS] Application authentication succeeded.\n";

    // 6 - Verify AID again after authentication
    const auto cryptoAfterAuth = desfireChip->getCrypto();

    if (!cryptoAfterAuth)
        throw std::runtime_error("DESFire crypto context is not initialized after authentication.");

    if (cryptoAfterAuth->d_currentAid != DUOX_TEST_APPLICATION_AID)
        throw std::runtime_error("SAFETY FAILURE : current AID changed after authentication.");

    std::cout << "[PASS] Authenticated context is still the dedicated DUOX test application.\n";

    // 7 - Only now run ManageKeyPair tests
    std::cout << "\n[SAFETY] All preconditions satisfied.\n"
              << "[SAFETY] ManageKeyPair tests may now modify ECC keys ONLY inside the dedicated application.\n\n";

    
    // -------------------------------------------------------------------------
    // TEST 0 - AuthenticateEV2NonFirst using the crypto key store fallback
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 0] Verify AuthenticateEV2NonFirst key store fallback...\n";

        const auto desfireChip = std::dynamic_pointer_cast<logicalaccess::DESFireChip>(chip);

        if (!desfireChip)
            throw std::runtime_error("AuthenticateEV2NonFirst test failed : chip is not a DESFireChip.");

        const auto crypto = desfireChip->getCrypto();

        if (!crypto)
            throw std::runtime_error("AuthenticateEV2NonFirst test failed : crypto context is null.");

        if (crypto->d_currentAid != DUOX_TEST_APPLICATION_AID)
            throw std::runtime_error("AuthenticateEV2NonFirst test failed : unexpected current AID.");

        constexpr std::uint8_t TEST_KEY_SLOT = 0;
        constexpr std::uint8_t TEST_KEY_NO   = TEST_APPLICATION_AUTH_KEY_NO;

        const auto storedKey = crypto->getKey(TEST_KEY_SLOT, TEST_KEY_NO);

        if (!storedKey)
        {
            throw std::runtime_error("AuthenticateEV2NonFirst test failed : "
                                     "DESFireCrypto::getKey() returned null for the "
                                     "test application's authentication key.");
        }

        if (storedKey->getKeyType() != logicalaccess::DF_KEY_AES)
        {
            throw std::runtime_error("AuthenticateEV2NonFirst test failed : "
                "key returned by DESFireCrypto has the wrong key type.");
        }

        std::cout << "[PASS] DESFireCrypto contains the expected authentication key.\n";

        // Do NOT pass testAuthKey here : this is specifically testing the fallback path that retrieves
        // the authentication key from DESFireCrypto
        duoxCommands->authenticateEV2NonFirst(TEST_KEY_NO, nullptr);

        std::cout << "[PASS] AuthenticateEV2NonFirst succeeded using the crypto key store fallback.\n";

        // AuthenticateEV2NonFirst must not change the selected application
        const auto cryptoAfterAuth = desfireChip->getCrypto();

        if (!cryptoAfterAuth)
            throw std::runtime_error("AuthenticateEV2NonFirst test failed : crypto context "
                "became null after authentication.");

        if (cryptoAfterAuth->d_currentAid != DUOX_TEST_APPLICATION_AID)
            throw std::runtime_error("SAFETY FAILURE : AuthenticateEV2NonFirst changed the current application.");

        std::cout << "[PASS] Current AID remains the dedicated DUOX test application.\n";
    }

    /*
     * ManageKeyPair tests intentionally use Full communication mode
     * The test application is dedicated to these operations and its ECC write access is configured accordingly
     *
     * Tests covering Plain and MAC communication modes should be added separately
     * rather than mixing communication-mode coverage into these functional tests
     */

    
    // -------------------------------------------------------------------------
    // TEST 1 - Generate NIST P-256
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 1] Generate NIST P-256 key pair...\n";

        const auto publicKey = duoxCommands->manageKeyPair(
            TEST_ECC_KEY_SLOT_P256,
            logicalaccess::DUOXManageKeyPairOption::GenerateKeyPair,
            logicalaccess::DUOXCurveID::NIST_P256, DUOX_TEST_KEY_POLICY,
            DUOX_TEST_WRITE_ACCESS, DUOX_TEST_KUC_LIMIT);

        if (publicKey.empty())
            throw std::runtime_error("DUOX NIST P-256 generation returned an empty public key.");

        std::cout << "[PASS] NIST P-256 key pair generated.\n"
                  << "[INFO] Public key size : " << publicKey.size() << " bytes\n";
    }

    // -------------------------------------------------------------------------
    // TEST 2 - Generate brainpoolP256r1 in another ECC slot
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 2] Generate Brainpool P-256 R1 key pair...\n";

        const auto publicKey = duoxCommands->manageKeyPair(
            TEST_ECC_KEY_SLOT_BRAINPOOL,
            logicalaccess::DUOXManageKeyPairOption::GenerateKeyPair,
            logicalaccess::DUOXCurveID::BRAINPOOL_P256R1, DUOX_TEST_KEY_POLICY,
            DUOX_TEST_WRITE_ACCESS, DUOX_TEST_KUC_LIMIT);

        if (publicKey.empty())
            throw std::runtime_error("DUOX Brainpool P-256 R1 generation returned an empty public key.");

        std::cout << "[PASS] Brainpool P-256 R1 key pair generated.\n"
                  << "[INFO] Public key size : " << publicKey.size() << " bytes\n";
    }

    // -------------------------------------------------------------------------
    // TEST 3 - Import a 32-byte P-256 private key
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 3] Import P-256 private key...\n";

        /*const ByteVector testPrivateKey{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};*/

        // P-256 private scalar d = 1, encoded as a 32-byte big-endian value
        const ByteVector testPrivateKey{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

        if (testPrivateKey.size() != 32)
            throw std::runtime_error("Internal test error : test private key must be exactly 32 bytes.");

        const auto result = duoxCommands->manageKeyPair(
            TEST_ECC_KEY_SLOT_IMPORT,
            logicalaccess::DUOXManageKeyPairOption::ImportPrivateKey,
            logicalaccess::DUOXCurveID::NIST_P256, DUOX_TEST_KEY_POLICY,
            DUOX_TEST_WRITE_ACCESS, DUOX_TEST_KUC_LIMIT, testPrivateKey);

        // ImportPrivateKey is not expected to return a generated public key through this API
        if (!result.empty())
            throw std::runtime_error("DUOX P-256 private key import returned unexpected response data.");

        std::cout << "[PASS] P-256 private key imported.\n";
    }

    // -------------------------------------------------------------------------
    // TEST 4 - Update metadata of an existing ECC key
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 4] Update ECC key metadata...\n";

        /*
         * Test 4 is intentionally self-contained :
         * ensure the dedicated metadata-test slot contains an ECC key before attempting to update its metadata
         *
         * Do not rely on TEST 1/2 having been executed before this test
         */
        constexpr std::uint8_t TEST_ECC_KEY_SLOT_METADATA = 0x03;

        std::cout << "[INFO] Preparing ECC key slot 0x" << std::hex
                  << static_cast<unsigned int>(TEST_ECC_KEY_SLOT_METADATA) << std::dec
                  << " for metadata update...\n";

        const auto publicKey = duoxCommands->manageKeyPair(
            TEST_ECC_KEY_SLOT_METADATA,
            logicalaccess::DUOXManageKeyPairOption::GenerateKeyPair,
            logicalaccess::DUOXCurveID::NIST_P256, DUOX_TEST_KEY_POLICY,
            DUOX_TEST_WRITE_ACCESS, DUOX_TEST_KUC_LIMIT);

        if (publicKey.empty())
            throw std::runtime_error("DUOX metadata test setup failed : ECC key generation returned an empty public key.");

        std::cout << "[INFO] ECC key successfully created in dedicated metadata-test slot.\n";

        const auto result = duoxCommands->manageKeyPair(
            TEST_ECC_KEY_SLOT_METADATA,
            logicalaccess::DUOXManageKeyPairOption::UpdateMetadata,
            logicalaccess::DUOXCurveID::NIST_P256, DUOX_TEST_KEY_POLICY,
            DUOX_TEST_WRITE_ACCESS, DUOX_TEST_KUC_LIMIT);

        // UpdateMetadata is not expected to return any response data
        if (!result.empty())
            throw std::runtime_error("DUOX ECC metadata update returned unexpected response data.");

        std::cout << "[PASS] ECC key metadata updated.\n";
    }
    
    // -------------------------------------------------------------------------
    // TEST 5 - Create a CA Root Key
    // -------------------------------------------------------------------------

    // Exercise the interaction between ManageKeyPair and ManageCARootKey by generating a public key and
    // using it immediately as the CA Root Key input
    {
        std::cout << "\n[TEST 5] Create CA Root Key...\n";

        /*
         * Generate a fresh P-256 key pair and use its public key as the input for ManageCARootKey
         *
         * This verifies that a public key returned by ManageKeyPair can be consumed directly by ManageCARootKey
         */
        const auto publicKey = duoxCommands->manageKeyPair(
            TEST_ECC_KEY_SLOT_P256,
            logicalaccess::DUOXManageKeyPairOption::GenerateKeyPair,
            logicalaccess::DUOXCurveID::NIST_P256, DUOX_TEST_KEY_POLICY,
            DUOX_TEST_WRITE_ACCESS, DUOX_TEST_KUC_LIMIT);

        if (publicKey.size() != 65)
            throw std::runtime_error(
                "DUOX CA Root Key test setup failed : generated P-256 "
                "public key must be exactly 65 bytes.");

        if (publicKey[0] != 0x04)
            throw std::runtime_error(
                "DUOX CA Root Key test setup failed : generated public key "
                "is not an uncompressed ECC public key.");

        duoxCommands->manageCARootKey(
            TEST_CA_ROOT_KEY_SLOT, logicalaccess::DUOXCurveID::NIST_P256,
            DUOX_TEST_CA_ACCESS_RIGHTS, DUOX_TEST_CA_WRITE_ACCESS,
            DUOX_TEST_CA_READ_ACCESS, DUOX_TEST_CA_CRL_FILE, DUOX_TEST_CA_CRL_FILE_AID,
            publicKey, DUOX_TEST_CA_ISSUER);

        std::cout << "[PASS] CA Root Key created successfully.\n";
    }

    // -------------------------------------------------------------------------
    // TEST 6 - Export ECC public key
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 6] Export ECC public key...\n";

        constexpr std::size_t EXPECTED_P256_PUBLIC_KEY_SIZE = 65U;

        const ByteVector exportedKey = duoxCommands->exportKey(TEST_CA_ROOT_KEY_SLOT, DUOX_COMM_MODE);

        if (exportedKey.size() != EXPECTED_P256_PUBLIC_KEY_SIZE)
            throw std::runtime_error("DUOX ExportKey returned an invalid P-256 public key size.");

        if (exportedKey[0] != 0x04)
        {
            throw std::runtime_error(
                "DUOX ExportKey returned a P-256 public key which is not "
                "encoded as an uncompressed ECC point.");
        }

        std::cout << "[PASS] DUOX P-256 public key exported successfully.\n";
        std::cout << "[INFO] Exported public key size : " << exportedKey.size()
                  << " bytes\n";
    }

    // -------------------------------------------------------------------------
    // TEST 7 - Get base key settings
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 7] Get DUOX application key settings...\n";

        const auto settings = duoxCommands->getKeySettings();

        if (settings.responseType != logicalaccess::DUOXGetKeySettingsResponseType::KeySettings)
            throw std::runtime_error("DUOX GetKeySettings returned an unexpected response type.");

        if (settings.piccLevel)
            throw std::runtime_error("DUOX application GetKeySettings incorrectly reports PICC level.");

        /*
         * The test application was created with :
         *
         *     createApplication(AID, KS_DEFAULT, 2, DF_KEY_AES)
         *
         * Therefore it must contain exactly two AES keys.
         */
        if (settings.numberOfKeys != 2)
            throw std::runtime_error("DUOX GetKeySettings returned an unexpected number of keys : expected 2, received " +
                                     std::to_string(settings.numberOfKeys) + ".");

        if (settings.keyType != static_cast<std::uint8_t>(KEY_TYPE_AES128) &&
            settings.keyType != static_cast<std::uint8_t>(KEY_TYPE_AES256))
            throw std::runtime_error("DUOX GetKeySettings returned an invalid AES key type.");

        // The application was created without an application key-set configuration
        // so the response should contain only the two base bytes
        if (settings.hasApplicationKeySetSettings)
            throw std::runtime_error("DUOX GetKeySettings unexpectedly returned application key-set settings.");

        if (!settings.eccPrivateKeys.empty())
            throw std::runtime_error("DUOX base GetKeySettings unexpectedly returned ECC metadata.");

        if (!settings.caRootKeys.empty())
            throw std::runtime_error("DUOX base GetKeySettings unexpectedly returned CA Root Key metadata.");

        std::cout << "[PASS] DUOX application key settings retrieved successfully.\n";
        std::cout << "[INFO] Number of keys : "
                  << static_cast<unsigned int>(settings.numberOfKeys) << '\n';
        std::cout << "[INFO] Key type       : 0x" << std::hex
                  << static_cast<unsigned int>(settings.keyType) << std::dec << '\n';
    }

    // -------------------------------------------------------------------------
    // TEST 8 - Verify default GetKeySettings overload
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 8] Verify default GetKeySettings overload...\n";

        const auto defaultSettings = duoxCommands->getKeySettings();
        const auto explicitSettings = duoxCommands->getKeySettings(GET_KEY_SETTINGS_OPTION_NONE);

        if (defaultSettings.responseType != explicitSettings.responseType)
            throw std::runtime_error("DUOX GetKeySettings() and GetKeySettings(0x00) returned different response types.");

        if (defaultSettings.piccLevel != explicitSettings.piccLevel)
            throw std::runtime_error("DUOX GetKeySettings() and GetKeySettings(0x00) returned different PICC-level state.");

        if (defaultSettings.keySettings != explicitSettings.keySettings)
            throw std::runtime_error("DUOX GetKeySettings() and GetKeySettings(0x00) "
                "returned different KeySettings values.");

        if (defaultSettings.maxNoOfKeys != explicitSettings.maxNoOfKeys)
            throw std::runtime_error("DUOX GetKeySettings() and GetKeySettings(0x00) "
                "returned different MaxNoOfKeys values.");

        if (defaultSettings.numberOfKeys != explicitSettings.numberOfKeys)
            throw std::runtime_error("DUOX GetKeySettings() and GetKeySettings(0x00) returned different key counts.");

        if (defaultSettings.keyType != explicitSettings.keyType)
            throw std::runtime_error("DUOX GetKeySettings() and GetKeySettings(0x00) returned different key types.");

        if (defaultSettings.hasApplicationKeySetSettings != explicitSettings.hasApplicationKeySetSettings)
        {
            throw std::runtime_error("DUOX GetKeySettings() and GetKeySettings(0x00) returned different "
                "application key-set state.");
        }

        std::cout << "[PASS] Default GetKeySettings overload behaves identically to option 0x00.\n";
    }

    // -------------------------------------------------------------------------
    // TEST 9 - Get ECC private key metadata
    // -------------------------------------------------------------------------

    // Note that the order of entries returned by GetKeySettings is not used as part of the semantic test
    // We don't explicitly identify each key by its KeyNo
    /*
     * The test application is expected to contain exactly four ECC private key metadata entries :
     *   KeyNo 0 : generated NIST P-256
     *   KeyNo 1 : generated Brainpool P-256 R1
     *   KeyNo 2 : imported NIST P-256
     *   KeyNo 3 : metadata update test key
     * Do not rely on the order in which the card returns these entries
     * The semantic identifier is entry.keyNo
     */
    {
        std::cout << "\n[TEST 9] Get DUOX ECC private key metadata...\n";

        const auto settings = duoxCommands->getKeySettings(GET_KEY_SETTINGS_OPTION_ECC_PRIVATE_KEY);

        if (settings.responseType != logicalaccess::DUOXGetKeySettingsResponseType::ECCPrivateKeyMetadata)
            throw std::runtime_error("DUOX ECC GetKeySettings returned an unexpected response type.");

        if (settings.piccLevel)
            throw std::runtime_error("DUOX ECC GetKeySettings incorrectly reports PICC level.");

        if (settings.eccPrivateKeys.size() != EXPECTED_ECC_METADATA_COUNT)
        {
            throw std::runtime_error(
                "DUOX ECC metadata returned an unexpected number of entries : expected " +
                std::to_string(EXPECTED_ECC_METADATA_COUNT) + ", received " +
                std::to_string(settings.eccPrivateKeys.size()) + ".");
        }

        // Slot 0 : generated NIST P-256
        {
            const auto &entry = settings.eccPrivateKeys[0];

            if (entry.keyNo != TEST_ECC_KEY_SLOT_P256)
                throw std::runtime_error("DUOX ECC metadata slot 0 returned an unexpected key number.");

            if (entry.curveId != logicalaccess::DUOXCurveID::NIST_P256)
                throw std::runtime_error("DUOX ECC metadata slot 0 returned an unexpected CurveID.");

            if (entry.keyPolicy != DUOX_TEST_KEY_POLICY)
                throw std::runtime_error("DUOX ECC metadata slot 0 returned an unexpected KeyPolicy.");

            if (entry.writeAccess != DUOX_TEST_WRITE_ACCESS)
                throw std::runtime_error("DUOX ECC metadata slot 0 returned an unexpected WriteAccess.");

            if (entry.keyUsageCtrLimit != DUOX_TEST_KUC_LIMIT)
                throw std::runtime_error("DUOX ECC metadata slot 0 returned an unexpected KeyUsageCtrLimit.");

            if (entry.keyUsageCtr != 0)
                throw std::runtime_error("DUOX ECC metadata slot 0 returned an unexpected KeyUsageCtr.");
        }

        // Slot 1 : generated Brainpool P-256 R1
        {
            const auto &entry = settings.eccPrivateKeys[1];

            if (entry.keyNo != TEST_ECC_KEY_SLOT_BRAINPOOL)
                throw std::runtime_error("DUOX ECC metadata slot 1 returned an unexpected key number.");

            if (entry.curveId != logicalaccess::DUOXCurveID::BRAINPOOL_P256R1)
                throw std::runtime_error("DUOX ECC metadata slot 1 returned an unexpected CurveID.");

            if (entry.keyPolicy != DUOX_TEST_KEY_POLICY)
                throw std::runtime_error("DUOX ECC metadata slot 1 returned an unexpected KeyPolicy.");

            if (entry.writeAccess != DUOX_TEST_WRITE_ACCESS)
                throw std::runtime_error("DUOX ECC metadata slot 1 returned an unexpected WriteAccess.");

            if (entry.keyUsageCtrLimit != DUOX_TEST_KUC_LIMIT)
                throw std::runtime_error("DUOX ECC metadata slot 1 returned an unexpected KeyUsageCtr.");

            if (entry.keyUsageCtr != 0)
                throw std::runtime_error("DUOX ECC metadata slot 1 returned an unexpected KeyUsageCtr.");
        }

        // Slot 2 : imported P-256
        {
            const auto &entry = settings.eccPrivateKeys[2];

            if (entry.keyNo != TEST_ECC_KEY_SLOT_IMPORT)
                throw std::runtime_error("DUOX ECC metadata slot 2 returned an unexpected key number.");

            if (entry.curveId != logicalaccess::DUOXCurveID::NIST_P256)
                throw std::runtime_error("DUOX ECC metadata slot 2 returned an unexpected CurveID.");

            if (entry.keyPolicy != DUOX_TEST_KEY_POLICY)
                throw std::runtime_error("DUOX ECC metadata slot 2 returned an unexpected KeyPolicy.");

            if (entry.writeAccess != DUOX_TEST_WRITE_ACCESS)
                throw std::runtime_error("DUOX ECC metadata slot 2 returned an unexpected WriteAccess.");

            if (entry.keyUsageCtrLimit != DUOX_TEST_KUC_LIMIT)
                throw std::runtime_error("DUOX ECC metadata slot 2 returned an unexpected KeyUsageCtrLimit.");

            if (entry.keyUsageCtr != 0)
                throw std::runtime_error("DUOX ECC metadata slot 2 returned an unexpected KeyUsageCtr.");
        }

        // Slot 3 : metadata update test key
        {
            const auto &entry = settings.eccPrivateKeys[3];

            constexpr std::uint8_t TEST_ECC_KEY_SLOT_METADATA = 0x03;

            if (entry.keyNo != TEST_ECC_KEY_SLOT_METADATA)
                throw std::runtime_error("DUOX ECC metadata slot 3 returned an unexpected key number.");

            if (entry.curveId != logicalaccess::DUOXCurveID::NIST_P256)
                throw std::runtime_error("DUOX ECC metadata slot 3 returned an unexpected CurveID.");

            if (entry.keyPolicy != DUOX_TEST_KEY_POLICY)
                throw std::runtime_error("DUOX ECC metadata slot 3 returned an unexpected KeyPolicy.");

            if (entry.writeAccess != DUOX_TEST_WRITE_ACCESS)
                throw std::runtime_error("DUOX ECC metadata slot 3 returned an unexpected WriteAccess.");

            if (entry.keyUsageCtrLimit != DUOX_TEST_KUC_LIMIT)
                throw std::runtime_error("DUOX ECC metadata slot 3 returned an unexpected KeyUsageCtrLimit.");

            if (entry.keyUsageCtr != 0)
                throw std::runtime_error("DUOX ECC metadata slot 3 returned an unexpected KeyUsageCtr.");
        }

        std::cout << "[PASS] DUOX ECC private key metadata retrieved and validated.\n";

        for (const auto &entry : settings.eccPrivateKeys)
        {
            std::cout << "[INFO] ECC slot " << static_cast<unsigned int>(entry.keyNo)
                      << " : CurveID=" << static_cast<unsigned int>(entry.curveId)
                      << ", KeyPolicy=0x" << std::hex << entry.keyPolicy
                      << ", WriteAccess=0x"
                      << static_cast<unsigned int>(entry.writeAccess)
                      << ", KUC limit=" << std::dec << entry.keyUsageCtrLimit
                      << ", KUC=" << entry.keyUsageCtr << '\n';
        }
    }

    // -------------------------------------------------------------------------
    // TEST 10 - Get CA Root Key metadata
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 10] Get DUOX CA Root Key metadata...\n";

        const auto settings = duoxCommands->getKeySettings(GET_KEY_SETTINGS_OPTION_CA_ROOT_KEY);

        if (settings.responseType != logicalaccess::DUOXGetKeySettingsResponseType::CARootKeyMetadata)
        {
            throw std::runtime_error("DUOX CA Root Key GetKeySettings returned an unexpected response type.");
        }

        if (settings.piccLevel)
            throw std::runtime_error("DUOX CA Root Key GetKeySettings incorrectly reports PICC level.");

        if (settings.caRootKeys.size() != EXPECTED_CA_ROOT_METADATA_COUNT)
        {
            throw std::runtime_error("DUOX CA Root Key metadata returned an unexpected "
                                     "number of entries : expected " +
                                     std::to_string(EXPECTED_CA_ROOT_METADATA_COUNT) +
                                     ", received " +
                                     std::to_string(settings.caRootKeys.size()) + ".");
        }

        const auto &entry = settings.caRootKeys[0];

        if (entry.keyNo != TEST_CA_ROOT_KEY_SLOT)
            throw std::runtime_error("DUOX CA Root Key metadata returned an unexpected key number.");

        if (entry.curveId != logicalaccess::DUOXCurveID::NIST_P256)
            throw std::runtime_error("DUOX CA Root Key metadata returned an unexpected CurveID.");

        if (entry.accessRights != DUOX_TEST_CA_ACCESS_RIGHTS)
            throw std::runtime_error("DUOX CA Root Key metadata returned unexpected AccessRights.");

        if (entry.writeAccess != DUOX_TEST_CA_WRITE_ACCESS)
            throw std::runtime_error("DUOX CA Root Key metadata returned unexpected WriteAccess.");

        if (entry.readAccess != DUOX_TEST_CA_READ_ACCESS)
            throw std::runtime_error("DUOX CA Root Key metadata returned unexpected ReadAccess.");

        if (entry.crlFile != DUOX_TEST_CA_CRL_FILE)
            throw std::runtime_error("DUOX CA Root Key metadata returned unexpected CRLFile.");

        if (entry.crlFileAid != DUOX_TEST_CA_CRL_FILE_AID)
            throw std::runtime_error("DUOX CA Root Key metadata returned unexpected CRLFileAID.");

        /*
         * These two assertions specifically exercise the semantic rule
         * implemented by getKeySettings():
         *
         * CRL disabled => CRLFile == 0 and CRLFileAID == 0.
         */
        if (entry.crlFile != 0x00)
            throw std::runtime_error("DUOX CA Root Key metadata indicates an unexpected CRL file.");

        if (entry.crlFileAid != 0x000000)
            throw std::runtime_error("DUOX CA Root Key metadata indicates an unexpected CRL file AID.");

        std::cout << "[PASS] DUOX CA Root Key metadata retrieved and validated.\n";

        std::cout << "[INFO] CA Root Key slot : " << static_cast<unsigned int>(entry.keyNo) << '\n';

        std::cout << "[INFO] CurveID          : " << static_cast<unsigned int>(entry.curveId) << '\n';

        std::cout << "[INFO] AccessRights     : 0x" << std::hex << entry.accessRights << '\n';

        std::cout << "[INFO] WriteAccess      : 0x" << static_cast<unsigned int>(entry.writeAccess) << '\n';

        std::cout << "[INFO] ReadAccess       : 0x" << static_cast<unsigned int>(entry.readAccess) << '\n';

        std::cout << "[INFO] CRLFile          : 0x" << static_cast<unsigned int>(entry.crlFile) << '\n';

        std::cout << "[INFO] CRLFileAID       : 0x" << std::setw(6) << std::setfill('0')
                  << entry.crlFileAid << std::dec << '\n';
    }

    // -------------------------------------------------------------------------
    // TEST 11 - Cross-check CA Root Key metadata against ExportKey
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 11] Cross-check CA Root Key metadata and ExportKey...\n";

        const auto metadata = duoxCommands->getKeySettings(GET_KEY_SETTINGS_OPTION_CA_ROOT_KEY);

        const auto exportedKey = duoxCommands->exportKey(TEST_CA_ROOT_KEY_SLOT, DUOX_COMM_MODE);

        const auto it =
            std::find_if(metadata.caRootKeys.begin(), metadata.caRootKeys.end(),
                         [](const logicalaccess::DUOXCARootKeyMetadata &entry)
                         { return entry.keyNo == TEST_CA_ROOT_KEY_SLOT; });

        if (it == metadata.caRootKeys.end())
            throw std::runtime_error("CA Root Key metadata does not contain the exported key slot.");

        if (it->curveId != logicalaccess::DUOXCurveID::NIST_P256)
            throw std::runtime_error("CA Root Key metadata and test configuration disagree on CurveID.");

        if (exportedKey.size() != EXPECTED_P256_PUBLIC_KEY_SIZE)
            throw std::runtime_error("ExportKey returned an unexpected public key size.");

        if (exportedKey[0] != 0x04)
            throw std::runtime_error("ExportKey returned a non-uncompressed P-256 public key.");

        std::cout << "[PASS] CA Root Key metadata is consistent with ExportKey.\n";
    }

    // -------------------------------------------------------------------------
    // TEST 12 - PICC-level GetKeySettings
    // -------------------------------------------------------------------------
    {
        std::cout << "\n[TEST 12] Get PICC-level DUOX key settings...\n";

        // This is a read-only operation
        // Selecting PICC level does not modify the card
        desfireCommands->selectApplication(PICC_LEVEL_AID);

        const auto settings = duoxCommands->getKeySettings();

        if (settings.responseType != logicalaccess::DUOXGetKeySettingsResponseType::KeySettings)
            throw std::runtime_error("DUOX PICC GetKeySettings returned an unexpected response type.");

        if (!settings.piccLevel)
            throw std::runtime_error("DUOX PICC GetKeySettings did not report PICC level.");

        // DUOX PICC level must contain exactly one AES key
        if (settings.numberOfKeys != 1)
            throw std::runtime_error("DUOX PICC GetKeySettings returned an unexpected "
                                     "number of keys : expected 1, received " +
                                     std::to_string(settings.numberOfKeys) + ".");

        if (settings.keyType != 0x80 && settings.keyType != 0xC0)
            throw std::runtime_error("DUOX PICC GetKeySettings returned an invalid key type.");

        if (settings.hasApplicationKeySetSettings)
            throw std::runtime_error("DUOX PICC GetKeySettings unexpectedly returned application key-set settings.");

        std::cout << "[PASS] PICC-level GetKeySettings validated successfully.\n";

        // Return to the dedicated test application immediately
        desfireCommands->selectApplication(DUOX_TEST_APPLICATION_AID);

        const auto crypto = std::dynamic_pointer_cast<logicalaccess::DESFireChip>(chip)->getCrypto();

        if (!crypto || crypto->d_currentAid != DUOX_TEST_APPLICATION_AID)
            throw std::runtime_error("SAFETY FAILURE : test application was not reselected after PICC GetKeySettings.");

        std::cout << "[PASS] Dedicated DUOX test application reselected.\n";
    }

    std::cout << "\n========================================\n"
              << " DUOX ManageKeyPair tests completed\n"
              << "========================================\n";
}

int main()
{
    /*
     * SAFETY RULES
     *
     * 1 - PICC selection is allowed ONLY for authentication required to create/delete DUOX_TEST_APPLICATION_AID
     * 2 - Never modify the PICC Master Key. PICC Master Key authentication is allowed only for creation/deletion
     *     of DUOX_TEST_APPLICATION_AID
     * 3 - Never call ChangeKey()
     * 4 - Never call SetConfiguration()
     * 5 - Never call InitializeKeySet()
     * 6 - Never call RollKeySet()
     * 7 - ONLY create/delete DUOX_TEST_APPLICATION_AID
     * 8 - NEVER create or delete any other application
     * 9 - All ECC operations are restricted to DUOX_TEST_APPLICATION_AID
     * 10 - The dedicated test application is deleted after the tests
     */

    // EraseCard provides a clean NV-memory baseline for the test suite
    // The DeleteTestApplication mode is intended for cases where preserving unrelated card content is required
    try
    {
        if (CARD_PREPARATION_MODE == DUOXCardPreparationMode::EraseCard)
        {
            std::cout << "[WARNING] CARD_PREPARATION_MODE = EraseCard\n"
                      << "[WARNING] ALL applications and files will be deleted.\n";
        }
        else
        {
            std::cout << "[INFO] CARD_PREPARATION_MODE = DeleteTestApplication\n"
                      << "[INFO] Only the dedicated test application may be deleted.\n";
        }

        const auto readerConfiguration = createReaderConfiguration();
        const auto chip = waitForCard(readerConfiguration);
        const auto reader = readerConfiguration->getReaderUnit();

        if (!reader)
            throw std::runtime_error("Reader disappeared after card connection.");

        std::cout << "[INFO] Card inserted on reader \"" << reader->getConnectedName() << "\"." << '\n';
        const auto uid = reader->getNumber(chip);

        std::cout << "[INFO] Card type : " << chip->getCardType() << '\n'
                  << "[INFO] Card UID  : " << logicalaccess::BufferHelper::getHex(uid)
                  << '\n';

        if (!isDUOXCard(chip))
        {
            std::cout << "[INFO] Card is not a DUOX card. Nothing will be modified.\n";
            reader->disconnect();
            return EXIT_SUCCESS;
        }

        std::cout << "[INFO] Card is a DUOX card.\n";

        runDUOXManageKeyPairTests(chip);

        reader->disconnect();
        std::cout << "[INFO] Tests completed successfully." << std::endl;
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "[ERROR] " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (...)
    {
        std::cerr << "[ERROR] Unknown exception." << std::endl;
        return EXIT_FAILURE;
    }
}