/*
MIT License

Copyright (c) 2022 Petr Muzikant

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "InfinitEID.hpp"

#include "pcsc-common.hpp"

using namespace pcsc_cpp;

namespace
{

const byte_vector SELECT_MAIN_AID {0x00, 0xA4, 0x04, 0x00, 0x08, 0x01, 0x02,
                                   0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

const byte_vector SELECT_MASTER_FILE {0x00, 0xA4, 0x00, 0x0C, 0x00};

const std::vector<byte_vector> SELECT_AUTH_CERT_FILE = {
    SELECT_MAIN_AID,
    {0x00, 0xA4, 0x02, 0x0C, 0x02, 0xAA, 0xCE},
};
const std::vector<byte_vector> SELECT_SIGN_CERT_FILE = {
    SELECT_MAIN_AID,
    {0x00, 0xA4, 0x02, 0x0C, 0x02, 0xDD, 0xCE},
};

const byte_vector::value_type AUTH_PIN_REFERENCE = 0x01;
const byte_vector::value_type SIGNING_PIN_REFERENCE = 0x02;

} // namespace

namespace electronic_id
{

byte_vector InfinitEID::getCertificateImpl(const CertificateType type) const
{
    return electronic_id::getCertificate(
        *card, type.isAuthentication() ? SELECT_AUTH_CERT_FILE : SELECT_SIGN_CERT_FILE);
}

byte_vector InfinitEID::signWithAuthKeyImpl(const byte_vector& pin,
                                                const byte_vector& hash) const
{
    verifyPin(*card, AUTH_PIN_REFERENCE, pin, authPinMinMaxLength().first, 0, 0);
    return internalAuthenticate(*card, hash, name());
}

ElectronicID::PinRetriesRemainingAndMax InfinitEID::authPinRetriesLeftImpl() const
{
    return pinRetriesLeft(AUTH_PIN_REFERENCE);
}

const std::set<SignatureAlgorithm>& InfinitEID::supportedSigningAlgorithms() const
{
    const static std::set<SignatureAlgorithm> ES_ALGOS = {SignatureAlgorithm::ES256};
    return ES_ALGOS;
}

ElectronicID::Signature InfinitEID::signWithSigningKeyImpl(const byte_vector& pin,
                                                               const byte_vector& hash,
                                                               const HashAlgorithm hashAlgo) const
{
    verifyPin(*card, SIGNING_PIN_REFERENCE, pin, signingPinMinMaxLength().first, 0, 0);
    return {computeSignature(*card, hash, name()), {SignatureAlgorithm::ES256, hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax InfinitEID::signingPinRetriesLeftImpl() const
{
    return pinRetriesLeft(SIGNING_PIN_REFERENCE);
}

ElectronicID::PinRetriesRemainingAndMax
InfinitEID::pinRetriesLeft(byte_vector::value_type pinReference) const
{
    const pcsc_cpp::CommandApdu GET_RETRIES_LEFT {
        0x00, 0x26, 0x00, pinReference, pcsc_cpp::byte_vector(), 0x01};
    const auto response = card->transmit(GET_RETRIES_LEFT);
    if (!response.isOK()) {
        THROW(SmartCardError,
              "Command GET DATA failed with error " + pcsc_cpp::bytes2hexstr(response.toBytes()));
    }
    return {uint8_t(response.data[0]), uint8_t(response.data[1])};
}

} // namespace electronic_id
