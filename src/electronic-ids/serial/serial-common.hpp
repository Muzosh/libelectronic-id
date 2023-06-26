#pragma once

#include "electronic-id/electronic-id.hpp"

#include <algorithm>

using namespace serial_cpp;

namespace electronic_id
{

inline electronic_id::byte_vector getCertificate(serial_cpp::SerialDevice& serialDevice,
                                                 const electronic_id::byte_vector getCertCmd)
{
    // Get certificate length by sending GET_CERTIFICATE command with length expected = 4
    const auto length = serial_cpp::readCertificateLengthFromAsn1(
        serialDevice, SerialDeviceCommandApdu(SerialDeviceCommandApdu::fromBytes(getCertCmd), 4));

    // Send GET_CERTIFICATE command with length expected = length
    SerialDeviceResponseApdu result = serialDevice.transmit(
        SerialDeviceCommandApdu(SerialDeviceCommandApdu::fromBytes(getCertCmd), length));

    // Return certificate
    return result.data;
}

inline electronic_id::byte_vector
addPaddingToPin(const electronic_id::byte_vector& pin, size_t paddingLength,
                electronic_id::byte_vector::value_type paddingChar)
{
    auto paddedPin = pin;
    paddedPin.resize(std::max(pin.size(), paddingLength), paddingChar);
    return paddedPin;
}

inline void verifyPin(serial_cpp::SerialDevice& serialDevice,
                      electronic_id::byte_vector::value_type mode,
                      const electronic_id::byte_vector& pin, size_t pinMinLength,
                      size_t paddingLength, electronic_id::byte_vector::value_type paddingChar)
{
    const serial_cpp::SerialDeviceCommandApdu VERIFY_PIN {0xB1, mode, 0x00};
    serial_cpp::SerialDeviceResponseApdu response;

    if (serialDevice.hasPinPad) {
        // not implemented yet
        throw VerifyPinFailed(VerifyPinFailed::Status::PIN_ENTRY_DISABLED,
                              byte_vector(pinMinLength));
        // const auto verifyPin =
        //     serial_cpp::SerialDeviceCommandApdu {VERIFY_PIN, addPaddingToPin({}, paddingLength,
        //     paddingChar)};
        // response = card.transmitCTL(verifyPin, 0, uint8_t(pinMinLength));
    } else {
        const auto verifyPin = serial_cpp::SerialDeviceCommandApdu {
            VERIFY_PIN, addPaddingToPin(pin, paddingLength, paddingChar)};

        response = serialDevice.transmit(verifyPin);
    }

    if (response.isOK()) {
        return;
    }

    using Status = serial_cpp::SerialDeviceResponseApdu::Status;
    using serial_cpp::toSW;

    switch (response.toSW()) {
    // Fail, retry allowed unless SW2 == 0xc0.
    case toSW(Status::VERIFICATION_FAILED, 0xc0):
    case toSW(Status::PIN_BLOCKED, 0x00):
        throw VerifyPinFailed(VerifyPinFailed::Status::PIN_BLOCKED, response.toBytes());
    // // Fail, PIN pad PIN entry errors, retry allowed.
    // case toSW(Status::VERIFICATION_CANCELLED, 0x00):
    //     throw VerifyPinFailed(VerifyPinFailed::Status::PIN_ENTRY_TIMEOUT, response.toBytes());
    // case toSW(Status::VERIFICATION_CANCELLED, 0x01):
    //     throw VerifyPinFailed(VerifyPinFailed::Status::PIN_ENTRY_CANCEL, response.toBytes());
    // case toSW(Status::VERIFICATION_CANCELLED, 0x03):
    //     throw VerifyPinFailed(VerifyPinFailed::Status::INVALID_PIN_LENGTH, response.toBytes());
    // case toSW(Status::VERIFICATION_CANCELLED, 0x04):
    //     throw VerifyPinFailed(VerifyPinFailed::Status::PIN_ENTRY_DISABLED, response.toBytes());
    // Fail, invalid PIN length, retry allowed.
    // case toSW(Status::WRONG_LENGTH, 0x00):
    // case toSW(Status::WRONG_PARAMETERS, 0x80):
    //     throw VerifyPinFailed(VerifyPinFailed::Status::INVALID_PIN_LENGTH, response.toBytes());
    // Fail, retry not allowed.
    // case toSW(Status::COMMAND_NOT_ALLOWED, 0x82):
    //     throw VerifyPinFailed(VerifyPinFailed::Status::PIN_BLOCKED, response.toBytes());
    default:
        if (response.sw1 == Status::VERIFICATION_FAILED) {
            throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED, response.toBytes(),
                                  response.sw2 & 0x0f);
        }
        break;
    }

    // There are other known response codes like 0x6985 (old and new are PIN same), 0x6402
    // (re-entered PIN is different) that only apply during PIN change, we treat them as unknown
    // errors here.

    // Other unknown errors.
    throw VerifyPinFailed(VerifyPinFailed::Status::UNKNOWN_ERROR, response.toBytes());
}

inline electronic_id::byte_vector internalAuthenticate(serial_cpp::SerialDevice& serialDevice,
                                                       const unsigned char algo,
                                                       const unsigned short le,
                                                       const electronic_id::byte_vector& hash,
                                                       const std::string& name)
{
    static const serial_cpp::SerialDeviceCommandApdu INTERNAL_AUTHENTICATE {
        0xA6, 0x01, algo, {}, le};

    auto internalAuth = serial_cpp::SerialDeviceCommandApdu {INTERNAL_AUTHENTICATE, hash};

    const auto response = serialDevice.transmit(internalAuth);

    if (response.sw1 == serial_cpp::SerialDeviceResponseApdu::WRONG_LENGTH) {
        THROW(SDeviceError,
              name + ": Wrong data length in command INTERNAL AUTHENTICATE argument: "
                  + serial_cpp::bytes2hexstr(response.toBytes()));
    }
    if (!response.isOK()) {
        THROW(SDeviceError,
              name + ": Command INTERNAL AUTHENTICATE failed with error "
                  + serial_cpp::bytes2hexstr(response.toBytes()));
    }

    return response.data;
}

inline electronic_id::byte_vector computeSignature(serial_cpp::SerialDevice& serialDevice,
                                                   const unsigned char algo,
                                                   const unsigned short le,
                                                   const electronic_id::byte_vector& hash,
                                                   const std::string& name)
{
    static const serial_cpp::SerialDeviceCommandApdu COMPUTE_SIGNATURE {0xA6, 0x02, algo, {}, le};

    auto signature = serial_cpp::SerialDeviceCommandApdu {COMPUTE_SIGNATURE, hash};

    const auto response = serialDevice.transmit(signature);

    if (response.sw1 == serial_cpp::SerialDeviceResponseApdu::WRONG_LENGTH) {
        THROW(SDeviceError,
              name + ": Wrong data length in command COMPUTE SIGNATURE argument: "
                  + serial_cpp::bytes2hexstr(response.toBytes()));
    }
    if (!response.isOK()) {
        THROW(SDeviceError,
              name + ": Command COMPUTE SIGNATURE failed with error "
                  + serial_cpp::bytes2hexstr(response.toBytes()));
    }

    return response.data;
}

} // namespace electronic_id
