/*
 * Copyright (c) 2020-2022 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "electronic-ids/pcsc/EstEIDGemalto.hpp"
#include "electronic-ids/pcsc/EstEIDIDEMIA.hpp"
#include "electronic-ids/pcsc/FinEID.hpp"
#include "electronic-ids/pcsc/LatEIDIDEMIAv1.hpp"
#include "electronic-ids/pcsc/LatEIDIDEMIAv2.hpp"
#include "electronic-ids/serial/InfinitEIDPQ.hpp"

#include "electronic-ids/pkcs11/Pkcs11ElectronicID.hpp"
#include "electronic-ids/serial/SerialElectronicID.hpp"

#include "serial-cpp/serial-cpp-utils.hpp"
#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include "magic_enum/magic_enum.hpp"

#include <algorithm>
#include <functional>
#include <iomanip>
#include <map>
#include <numeric>
#include <sstream>
#include <string>
#include <utility>
#include <list>

#include <QtSerialPort/qserialportinfo.h>

using namespace pcsc_cpp;
using namespace serial_cpp;
using namespace electronic_id;
using namespace std::string_literals;

namespace
{

using ElectronicIDCardConstructor = std::function<ElectronicID::ptr(SmartCard::ptr&&)>;

#define ESTEID_GEMALTO_V3_5_8_CONSTUCTOR                                                           \
    [](SmartCard::ptr&& card) { return std::make_unique<EstEIDGemaltoV3_5_8>(std::move(card)); }

// Supported cards.
const std::map<byte_vector, ElectronicIDCardConstructor> SUPPORTED_ATRS = {
    // EstEID Gemalto v3.5.8 cold
    {{0x3b, 0xfa, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0xfe,
      0x65, 0x49, 0x44, 0x20, 0x2f, 0x20, 0x50, 0x4b, 0x49, 0x03},
     ESTEID_GEMALTO_V3_5_8_CONSTUCTOR},
    // EstEID Gemalto v3.5.8 warm
    {{0x3b, 0xfe, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0x80, 0x31, 0x80,
      0x66, 0x40, 0x90, 0xa4, 0x16, 0x2a, 0x00, 0x83, 0x0f, 0x90, 0x00, 0xef},
     ESTEID_GEMALTO_V3_5_8_CONSTUCTOR},
    // EstEID Idemia v1.0
    {{0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45, 0x1f, 0x83, 0x00,
      0x12, 0x23, 0x3f, 0x53, 0x65, 0x49, 0x44, 0x0f, 0x90, 0x00, 0xf1},
     [](SmartCard::ptr&& card) { return std::make_unique<EstEIDIDEMIAV1>(std::move(card)); }},
    // FinEID v3.0
    {{0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0xb8, 0x65, 0xb0,
      0x85, 0x03, 0x00, 0xef, 0x12, 0x00, 0xf6, 0x82, 0x90, 0x00},
     [](SmartCard::ptr&& card) { return std::make_unique<FinEIDv3>(std::move(card)); }},
    // FinEID v3.1
    {{0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0,
      0x85, 0x04, 0x02, 0x1B, 0x12, 0x00, 0xF6, 0x82, 0x90, 0x00},
     [](SmartCard::ptr&& card) { return std::make_unique<FinEIDv3>(std::move(card)); }},
    // LatEID Idemia v1.0
    {{0x3b, 0xdd, 0x18, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x90, 0x4c, 0x41,
      0x54, 0x56, 0x49, 0x41, 0x2d, 0x65, 0x49, 0x44, 0x90, 0x00, 0x8c},
     [](SmartCard::ptr&& card) { return std::make_unique<LatEIDIDEMIAV1>(std::move(card)); }},
    // LatEID Idemia v2.0
    {{0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45, 0x1f, 0x83, 0x00,
      0x12, 0x42, 0x8f, 0x53, 0x65, 0x49, 0x44, 0x0f, 0x90, 0x00, 0x20},
     [](SmartCard::ptr&& card) { return std::make_unique<LatEIDIDEMIAV2>(std::move(card)); }},
    // LitEID
    {{0x3b, 0xf8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x53, 0x6d, 0x61, 0x72, 0x74, 0x41,
      0x70, 0x70, 0xf8},
     [](SmartCard::ptr&& card) {
         return std::make_unique<Pkcs11ElectronicID>(std::move(card),
                                                     Pkcs11ElectronicIDType::LitEIDv2);
     }},
    {{0x3B, 0x9D, 0x18, 0x81, 0x31, 0xFC, 0x35, 0x80, 0x31, 0xC0, 0x69,
      0x4D, 0x54, 0x43, 0x4F, 0x53, 0x73, 0x02, 0x05, 0x05, 0xD3},
     [](SmartCard::ptr&& card) {
         return std::make_unique<Pkcs11ElectronicID>(std::move(card),
                                                     Pkcs11ElectronicIDType::LitEIDv3);
     }},
    // HrvEID
    {{0x3b, 0xff, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x00, 0x31, 0xb9, 0x64,
      0x04, 0x44, 0xec, 0xc1, 0x73, 0x94, 0x01, 0x80, 0x82, 0x90, 0x00, 0x12},
     [](SmartCard::ptr&& card) {
         return std::make_unique<Pkcs11ElectronicID>(std::move(card),
                                                     Pkcs11ElectronicIDType::HrvEID);
     }},
    // BelEIDV1_7
    {{0x3b, 0x98, 0x13, 0x40, 0x0a, 0xa5, 0x03, 0x01, 0x01, 0x01, 0xad, 0x13, 0x11},
     [](SmartCard::ptr&& card) {
         return std::make_unique<Pkcs11ElectronicID>(std::move(card),
                                                     Pkcs11ElectronicIDType::BelEIDV1_7);
     }},
    // BelEIDV1_8
    {{0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0x80, 0x65, 0xb0,
      0x85, 0x04, 0x01, 0x20, 0x12, 0x0f, 0xff, 0x82, 0x90, 0x00},
     [](SmartCard::ptr&& card) {
         return std::make_unique<Pkcs11ElectronicID>(std::move(card),
                                                     Pkcs11ElectronicIDType::BelEIDV1_8);
     }},
};

using ElectronicIDSerialDeviceConstructor = std::function<ElectronicID::ptr(SerialDevice::ptr&&)>;

// Supported serial devices
const std::map<byte_vector, ElectronicIDSerialDeviceConstructor> SUPPORTED_SIDS = {
    // InfinitEIDPQ ESP32
    {{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10},
     [](SerialDevice::ptr&& serialDevice) {
         return std::make_unique<InfinitEIDPQ>(std::move(serialDevice));
     }}};

inline std::string byteVectorToHexString(const byte_vector& bytes)
{
    std::ostringstream hexStringBuilder;

    hexStringBuilder << std::setfill('0') << std::hex;

    for (const auto byte : bytes) {
        hexStringBuilder << std::setw(2) << static_cast<short>(byte);
    }

    return hexStringBuilder.str();
}

const auto SUPPORTED_ALGORITHMS = std::map<std::string, HashAlgorithm> {
    {"SHA-224"s, HashAlgorithm::SHA224},    {"SHA-256"s, HashAlgorithm::SHA256},
    {"SHA-384"s, HashAlgorithm::SHA384},    {"SHA-512"s, HashAlgorithm::SHA512},
    {"SHA3-224"s, HashAlgorithm::SHA3_224}, {"SHA3-256"s, HashAlgorithm::SHA3_256},
    {"SHA3-384"s, HashAlgorithm::SHA3_384}, {"SHA3-512"s, HashAlgorithm::SHA3_512},
};

} // namespace

namespace electronic_id
{

/*
This container is required since we need to track already opened serial device ports, that can't be
opened twice. Otherwise, the next iteration of EidContainerEventMonitorThread would report no serial
device available and throw an exception in the middle of user interaction.
 */
std::list<SerialDeviceInfo::ptr> serialDeviceInfosOpenedByWebEid;

std::vector<EidContainerInfo::ptr> availableSupportedEidContainers()
{
    // Prepare pointers for exceptions as we don't want to throw them immediately
    // (there might be no cards, but we want to check for serial devices before throwing
    // AutoSelectFailed exception)
    std::unique_ptr<AutoSelectFailed> cardSelectionFailedEx;
    std::unique_ptr<AutoSelectFailed> serialDeviceSelectionFailedEx;

    // Prepare vectors for available cards and serial devices
    std::vector<CardInfo::ptr> availableCardInfos;
    std::vector<SerialDeviceInfo::ptr> availableSerialDeviceInfos;

    // Get available cards
    try {
        availableCardInfos = electronic_id::availableSupportedCards();
    } catch (AutoSelectFailed e) {
        cardSelectionFailedEx = std::make_unique<AutoSelectFailed>(std::move(e));
    }

    // Get available serial devices
    try {
        availableSerialDeviceInfos = electronic_id::availableSupportedSerialDevices();
    } catch (AutoSelectFailed e) {
        serialDeviceSelectionFailedEx = std::make_unique<AutoSelectFailed>(std::move(e));
    }

    // If both card and serial device selection failed, then we can throw exception
    if (cardSelectionFailedEx && serialDeviceSelectionFailedEx) {
        // TODO: Currently throws only exception from card selection as I feel like it has still
        // priority (Web-eID is mainly software for cards). Maybe use some generalized
        // exception?
        throw std::move(*cardSelectionFailedEx);
    }

    // Vector for all available eid containers (cards and serial devices) to return
    std::vector<electronic_id::EidContainerInfo::ptr> availableEidContainers;
    availableEidContainers.reserve(availableCardInfos.size() + availableSerialDeviceInfos.size());

    // Fill available eid containers vector with available cards
    for (const CardInfo::ptr& cardInfo : availableCardInfos) {
        availableEidContainers.push_back(cardInfo);
    }
    // Fill available eid containers vector with available serial devices
    for (const SerialDeviceInfo::ptr& serialDeviceInfo : availableSerialDeviceInfos) {
        availableEidContainers.push_back(serialDeviceInfo);
    }

    return availableEidContainers;
}

bool isCardSupported(const electronic_id::byte_vector& atr)
{
    return SUPPORTED_ATRS.count(atr);
}

bool isSerialDeviceSupported(const electronic_id::byte_vector& sid)
{
    return SUPPORTED_SIDS.count(sid);
}

ElectronicID::ptr getCardElectronicID(const pcsc_cpp::Reader& reader)
{
    try {
        const auto& eidConstructor = SUPPORTED_ATRS.at(reader.cardAtr);
        return eidConstructor(reader.connectToCard());
    } catch (const std::out_of_range&) {
        // It should be verified that the card is supported with isCardSupported() before
        // calling getCardElectronicID(), so it is a programming error if out_of_range occurs here.
        THROW(ProgrammingError,
              "Card with ATR '" + byteVectorToHexString(reader.cardAtr) + "' is not supported");
    }
}

ElectronicID::ptr getSerialDeviceElectronicID(const serial_cpp::SerialPortHandler& serialPort)
{
    try {
        const auto& eidConstructor = SUPPORTED_SIDS.at(serialPort.serialID);
        return eidConstructor(serialPort.connectToSerialDevice());
    } catch (const std::out_of_range&) {
        // It should be verified that the serialDevice is supported with isSerialDeviceSupported()
        // before calling getSerialDeviceElectronicID(), so it is a programming error if
        // out_of_range occurs here.
        SERIAL_CPP_THROW(ProgrammingError,
                         "Device with SID '" + byteVectorToHexString(serialPort.serialID)
                             + "' is not supported");
    }
}

bool ElectronicID::isSupportedSigningHashAlgorithm(const HashAlgorithm hashAlgo) const
{
    auto supported = supportedSigningAlgorithms();
    return std::any_of(supported.cbegin(), supported.cend(),
                       [hashAlgo](SignatureAlgorithm signAlgo) { return signAlgo == hashAlgo; });
}

AutoSelectFailed::AutoSelectFailed(Reason r) :
    Error(std::string("Auto-select card failed, reason: ") + std::string(magic_enum::enum_name(r))),
    _reason(r)
{
}

VerifyPinFailed::VerifyPinFailed(const Status s, const byte_vector responseBytes, const int8_t r) :
    Error(std::string("Verify PIN failed, status: ") + std::string(magic_enum::enum_name(s))
          + (responseBytes.empty() ? ", response: " + pcsc_cpp::bytes2hexstr(responseBytes) : "")),
    _status(s), _retries(r)
{
}

HashAlgorithm::HashAlgorithm(const std::string& algoName)
{
    if (!SUPPORTED_ALGORITHMS.count(algoName)) {
        THROW(ArgumentFatalError,
              "Hash algorithm is not valid, supported algorithms are "
                  + allSupportedAlgorithmNames());
    }
    value = SUPPORTED_ALGORITHMS.at(algoName);
}

HashAlgorithm::operator std::string() const
{
    const auto algoNameValuePair =
        std::find_if(SUPPORTED_ALGORITHMS.begin(), SUPPORTED_ALGORITHMS.end(),
                     [this](const auto& pair) { return pair.second == value; });
    return algoNameValuePair != SUPPORTED_ALGORITHMS.end() ? algoNameValuePair->first : "UNKNOWN";
}

std::string HashAlgorithm::allSupportedAlgorithmNames()
{
    static auto SUPPORTED_ALGORITHM_NAMES = std::string {};
    if (SUPPORTED_ALGORITHM_NAMES.empty()) {
        SUPPORTED_ALGORITHM_NAMES = std::accumulate(
            std::next(SUPPORTED_ALGORITHMS.begin()), SUPPORTED_ALGORITHMS.end(),
            SUPPORTED_ALGORITHMS.begin()->first,
            [](auto result, const auto& value) { return result + ", "s + value.first; });
    }
    return SUPPORTED_ALGORITHM_NAMES;
}

electronic_id::byte_vector HashAlgorithm::rsaOID(const HashAlgorithmEnum hash)
{
    switch (hash) {
    case HashAlgorithm::SHA224:
        return {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
    case HashAlgorithm::SHA256:
        return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    case HashAlgorithm::SHA384:
        return {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    case HashAlgorithm::SHA512:
        return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
    case HashAlgorithm::SHA3_224:
        return {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c};
    case HashAlgorithm::SHA3_256:
        return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20};
    case HashAlgorithm::SHA3_384:
        return {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30};
    case HashAlgorithm::SHA3_512:
        return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x0A, 0x05, 0x00, 0x04, 0x40};
    default:
        THROW(ArgumentFatalError, "No OID for algorithm " + std::string(HashAlgorithm(hash)));
    }
}

CertificateType::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

JsonWebSignatureAlgorithm::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

SignatureAlgorithm::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

} // namespace electronic_id
