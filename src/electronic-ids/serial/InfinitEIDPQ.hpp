#pragma once

#include "SerialElectronicID.hpp"

namespace electronic_id
{

class InfinitEIDPQ : public SerialElectronicID
{
public:
    InfinitEIDPQ(serial_cpp::SerialDevice::ptr _serialDevice) :
        SerialElectronicID(std::move(_serialDevice))
    {
        // Set options to default
        serialDevice().setup(serial_cpp::defaultSerialOptions);
    }

private:
    serial_cpp::byte_vector getCertificateImpl(const CertificateType type) const override;

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override
    {
        return JsonWebSignatureAlgorithm::CRYDI5;
    }
    PinMinMaxLength authPinMinMaxLength() const override { return {4, 256}; }
    PinRetriesRemainingAndMax authPinRetriesLeftImpl() const override;

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;
    PinMinMaxLength signingPinMinMaxLength() const override { return {6, 256}; }
    PinRetriesRemainingAndMax signingPinRetriesLeftImpl() const override;

    std::string name() const override { return "InfinitEIDPQ"; }
    Type type() const override { return ElectronicID::Type::InfinitEIDPQ; }

    serial_cpp::byte_vector signWithAuthKeyImpl(const serial_cpp::byte_vector& pin,
                                                const serial_cpp::byte_vector& hash) const override;

    Signature signWithSigningKeyImpl(const serial_cpp::byte_vector& pin,
                                     const serial_cpp::byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    serial_cpp::byte_vector sign(const HashAlgorithm hashAlgo, const serial_cpp::byte_vector& hash,
                                 const serial_cpp::byte_vector& pin,
                                 serial_cpp::byte_vector::value_type pinReference,
                                 PinMinMaxLength pinMinMaxLength,
                                 serial_cpp::byte_vector::value_type keyReference,
                                 serial_cpp::byte_vector::value_type signatureAlgo,
                                 serial_cpp::byte_vector::value_type LE) const;

    PinRetriesRemainingAndMax
    pinRetriesLeft(serial_cpp::byte_vector::value_type pinReference) const;
};

} // namespace electronic_id