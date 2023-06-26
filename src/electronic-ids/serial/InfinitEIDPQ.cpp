#include "InfinitEIDPQ.hpp"

#include "serial-common.hpp"

using namespace serial_cpp;

namespace
{

const byte_vector::value_type AUTH_PIN_REFERENCE = 0x01;
const byte_vector::value_type SIGNING_PIN_REFERENCE = 0x02;

const byte_vector SELECT_AUTH_CERT_FILE = {0xA4, AUTH_PIN_REFERENCE, 0xD5, 0x00, 0x00, 0x00, 0x00};
const byte_vector SELECT_SIGN_CERT_FILE = {0xA4, SIGNING_PIN_REFERENCE, 0xD5, 0x00, 0x00, 0x00,
                                           0x00};
} // namespace

namespace electronic_id
{

byte_vector InfinitEIDPQ::getCertificateImpl(const CertificateType type) const
{
    return electronic_id::getCertificate(
        *sDevice, type.isAuthentication() ? SELECT_AUTH_CERT_FILE : SELECT_SIGN_CERT_FILE);
}

byte_vector InfinitEIDPQ::signWithAuthKeyImpl(const byte_vector& pin, const byte_vector& hash) const
{
    verifyPin(*sDevice, AUTH_PIN_REFERENCE, pin, authPinMinMaxLength().first, 0, 0);
    return internalAuthenticate(*sDevice, 0xD5, (unsigned short)4595, hash, name());
}

ElectronicID::PinRetriesRemainingAndMax InfinitEIDPQ::authPinRetriesLeftImpl() const
{
    return pinRetriesLeft(AUTH_PIN_REFERENCE);
}

const std::set<SignatureAlgorithm>& InfinitEIDPQ::supportedSigningAlgorithms() const
{
    const static std::set<SignatureAlgorithm> DILITHIUM_ALGOS = {SignatureAlgorithm::DILITHIUM5};
    return DILITHIUM_ALGOS;
}

ElectronicID::Signature InfinitEIDPQ::signWithSigningKeyImpl(const byte_vector& pin,
                                                             const byte_vector& hash,
                                                             const HashAlgorithm hashAlgo) const
{
    verifyPin(*sDevice, SIGNING_PIN_REFERENCE, pin, signingPinMinMaxLength().first, 0, 0);
    return {computeSignature(*sDevice, 0xD5, (unsigned short)4595, hash, name()),
            {SignatureAlgorithm::DILITHIUM5, hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax InfinitEIDPQ::signingPinRetriesLeftImpl() const
{
    return pinRetriesLeft(SIGNING_PIN_REFERENCE);
}

ElectronicID::PinRetriesRemainingAndMax
InfinitEIDPQ::pinRetriesLeft(byte_vector::value_type pinReference) const
{
    const serial_cpp::SerialDeviceCommandApdu GET_RETRIES_LEFT {0xB2, pinReference, 0x00,
                                                                serial_cpp::byte_vector(), 0x02};
    const auto response = sDevice->transmit(GET_RETRIES_LEFT);
    if (!response.isOK()) {
        THROW(SerialDeviceError,
              "Command GET RETRIES LEFT failed with error "
                  + serial_cpp::bytes2hexstr(response.toBytes()));
    }
    return {uint8_t(response.data[0]), uint8_t(response.data[1])};
}

} // namespace electronic_id