#include <logicalaccess/plugins/cards/desfire/duoxchip.hpp>
#include <logicalaccess/cards/locationnode.hpp>

namespace logicalaccess
{

DUOXChip::DUOXChip()
    : DESFireEV3Chip(CHIP_DUOX)
{
}

std::shared_ptr<LocationNode> DUOXChip::getRootLocationNode()
{
    auto rootNode = DESFireEV3Chip::getRootLocationNode();
    rootNode->setName("MIFARE DUOX");

    return rootNode;
}

std::shared_ptr<CardService> DUOXChip::getService(CardServiceType serviceType)
{
    return DESFireEV3Chip::getService(serviceType);
}

} // namespace logicalaccess