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

#pragma once

#include "enums.hpp"

#include "pcsc-cpp/pcsc-cpp.hpp"
#include "serial-cpp/serial-cpp.hpp"

#include <memory>

namespace electronic_id
{
using byte_vector = std::vector<unsigned char>;

/** Interface for all electronic ID cards and tokens, contains cryptographic
 * operations and card/device information. */
class ElectronicID
{
public:
    using ptr = std::shared_ptr<ElectronicID>;
    using PinMinMaxLength = std::pair<size_t, size_t>;
    using PinRetriesRemainingAndMax = std::pair<uint8_t, int8_t>;
    using Signature = std::pair<electronic_id::byte_vector, SignatureAlgorithm>;

    enum Type {
        EstEID,
        FinEID,
        LatEID,
        LitEID,
        HrvEID,
        BelEIDV1_7,
        BelEIDV1_8,
        InfinitEIDPQ
#ifdef _WIN32
            MsCryptoApiEID,
#endif
    };

    virtual ~ElectronicID() = default;

    // Function for retrieving the authentication and signing certificates.
    virtual electronic_id::byte_vector getCertificate(const CertificateType type) const = 0;

    // Functions related to authentication.
    virtual JsonWebSignatureAlgorithm authSignatureAlgorithm() const = 0;

    virtual PinMinMaxLength authPinMinMaxLength() const = 0;

    virtual PinRetriesRemainingAndMax authPinRetriesLeft() const = 0;

    virtual electronic_id::byte_vector
    signWithAuthKey(const electronic_id::byte_vector& pin,
                    const electronic_id::byte_vector& hash) const = 0;

    // Functions related to signing.
    virtual const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const = 0;

    bool isSupportedSigningHashAlgorithm(const HashAlgorithm hashAlgo) const;

    virtual PinMinMaxLength signingPinMinMaxLength() const = 0;

    virtual PinRetriesRemainingAndMax signingPinRetriesLeft() const = 0;

    virtual Signature signWithSigningKey(const electronic_id::byte_vector& pin,
                                         const electronic_id::byte_vector& hash,
                                         const HashAlgorithm hashAlgo) const = 0;

    // General functions.
    virtual bool allowsUsingLettersAndSpecialCharactersInPin() const { return false; }
    virtual bool providesExternalPinDialog() const { return false; }
    virtual std::string name() const = 0;
    virtual Type type() const = 0;

    virtual pcsc_cpp::SmartCard const& smartcard() const { return *card; }
    virtual serial_cpp::SerialDevice const& serialDevice() const { return *sDevice; }

protected:
    ElectronicID(pcsc_cpp::SmartCard::ptr _card) : card(std::move(_card)) {}
    ElectronicID(serial_cpp::SerialDevice::ptr _serialDevice) : sDevice(std::move(_serialDevice)) {}

    pcsc_cpp::SmartCard::ptr card;
    serial_cpp::SerialDevice::ptr sDevice;

private:
    // The rule of five (C++ Core guidelines C.21).
    ElectronicID(const ElectronicID&) = delete;
    ElectronicID& operator=(const ElectronicID&) = delete;
    ElectronicID(ElectronicID&&) = delete;
    ElectronicID& operator=(ElectronicID&&) = delete;
};

bool isCardSupported(const electronic_id::byte_vector& atr);
bool isSerialDeviceSupported(const electronic_id::byte_vector& sid);

ElectronicID::ptr getCardElectronicID(const pcsc_cpp::Reader& reader);
ElectronicID::ptr getSerialDeviceElectronicID(const serial_cpp::SerialPortHandler& serialPort);

/** Aggregates reader and electronic ID objects for communicating with and inspecting the eID card.
 */

class EidContainerInfo
{
public:
    using ptr = std::shared_ptr<EidContainerInfo>;
    enum class ContainerType { CardInfo, SerialDeviceInfo };
    const ElectronicID& eid() const { return *_eid; }
    const ElectronicID::ptr eidPtr() const { return _eid; }
    ContainerType containerType() const { return _containerType; }
    const std::string eidContainerInfoName() const { return _eidContainerInfoName; }

    virtual ~EidContainerInfo() = default;

protected:
    EidContainerInfo(ElectronicID::ptr e, std::string eidContainerInfoName,
                     ContainerType containerType) :
        _eid(std::move(e)),
        _containerType(containerType), _eidContainerInfoName(eidContainerInfoName)
    {
    }

    ElectronicID::ptr _eid;
    ContainerType _containerType;
    std::string _eidContainerInfoName;
};

class CardInfo : public EidContainerInfo
{
public:
    using ptr = std::shared_ptr<CardInfo>;

    CardInfo(ElectronicID::ptr e, pcsc_cpp::Reader r) :
        EidContainerInfo(e, r.name + " : " + pcsc_cpp::bytes2hexstr(r.cardAtr),
                         EidContainerInfo::ContainerType::CardInfo),
        _reader(std::move(r))
    {
    }

    virtual ~CardInfo() = default;

    const pcsc_cpp::Reader& reader() const { return _reader; }

private:
    pcsc_cpp::Reader _reader;
};

class SerialDeviceInfo : public EidContainerInfo
{
public:
    using ptr = std::shared_ptr<SerialDeviceInfo>;

    SerialDeviceInfo(ElectronicID::ptr e, serial_cpp::SerialPortHandler p) :
        EidContainerInfo(e, p.qPortInfo.portName().toStdString(),
                         EidContainerInfo::ContainerType::SerialDeviceInfo),
        _serialPort(std::move(p))
    {
    }

    virtual ~SerialDeviceInfo() = default;

    const serial_cpp::SerialPortHandler& serialPort() const { return _serialPort; }

private:
    serial_cpp::SerialPortHandler _serialPort;
};

extern std::list<SerialDeviceInfo::ptr> serialDeviceInfosOpenedByWebEid;

/** Automatic eid container selection that either returns a vector of eid contianer info pointers
 * with available supported cards/devices or throws AutoSelectFailed. */
std::vector<EidContainerInfo::ptr> availableSupportedEidContainers();
std::vector<CardInfo::ptr> availableSupportedCards();
std::vector<SerialDeviceInfo::ptr> availableSupportedSerialDevices();

/** Base class for fatal errors in parameters or environment conditions that do not allow retrying.
 */
class FatalError : public std::runtime_error
{
protected:
    using std::runtime_error::runtime_error;
};

/** Fatal error caused by violating application logic pre-/post-conditions or invariants. */
class ProgrammingError : public FatalError
{
    using FatalError::FatalError;
};

/** Fatal error caused by input arguments. */
class ArgumentFatalError : public FatalError
{
    using FatalError::FatalError;
};

/** Base class for non-fatal errors, possibly allowing retry. */
class Error : public std::runtime_error
{
protected:
    using std::runtime_error::runtime_error;
};

/** An error that can possibly be mitigated by changing the smart card in the reader. */
class SmartCardChangeRequiredError : public Error
{
    using Error::Error;
};

/** Attempt to perform an operation with a wrong certificate type. */
class WrongCertificateTypeError : public Error
{
    using Error::Error;
};

/** Non-fatal error caused by the smart card services layer. */
class SmartCardError : public Error
{
    using Error::Error;
};

/** Non-fatal error caused by the serial device services layer. */
class SerialDeviceError : public Error
{
    using Error::Error;
};

/** Non-fatal error caused by the PKCS #11 layer. */
class Pkcs11Error : public Error
{
    using Error::Error;
};

/** Smart card was not present in its slot at the time that a PKCS#11 function was invoked. */
class Pkcs11TokenNotPresent : public Error
{
    using Error::Error;
};

/** Smart card was removed from its slot during the execution of a PKCS#11 function. */
class Pkcs11TokenRemoved : public Error
{
    using Error::Error;
};

#ifdef _WIN32
class MsCryptoApiError : public Error
{
    using Error::Error;
};
#endif

/** Communicates why auto-select failed to the caller. */
class AutoSelectFailed : public Error
{
public:
    enum class Reason {
        SERVICE_NOT_RUNNING,
        NO_READERS,
        SINGLE_READER_NO_CARD,
        SINGLE_READER_UNSUPPORTED_CARD,
        MULTIPLE_READERS_NO_CARD,
        MULTIPLE_READERS_NO_SUPPORTED_CARD,
        NO_SUPPORTED_SERIAL_DEVICES
    };

    explicit AutoSelectFailed(Reason r);

    Reason reason() const { return _reason; }

private:
    Reason _reason;
};

/** Communicates why PIN verification failed to the caller. */
class VerifyPinFailed : public Error
{
public:
    // Non-owning observing pointer.
    template <typename T>
    using observer_ptr = T*;

    enum class Status {
        RETRY_ALLOWED,
        INVALID_PIN_LENGTH,
        PIN_ENTRY_TIMEOUT,
        PIN_ENTRY_CANCEL,
        PIN_ENTRY_DISABLED,
        // Retry not allowed starting from PIN_BLOCKED.
        PIN_BLOCKED,
        UNKNOWN_ERROR
    };

    explicit VerifyPinFailed(const Status s, const byte_vector responseBytes = {},
                             const int8_t retries = 0);

    Status status() const { return _status; }
    int8_t retries() const { return _retries; }

private:
    Status _status;
    int8_t _retries;
};

} // namespace electronic_id
