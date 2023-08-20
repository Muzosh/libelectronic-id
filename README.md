# branch: feature-InfinitEID

This branch implements necessary code changes in the <https://github.com/Muzosh/Smart-Card-Authentication-On-The-Web> project. It adopts the InfinitEID interface in order to allow users to authenticate with custom-built non-state-issued smart cards.

## Installation

### Initialize Web-eID native application with InfinitEID implementation submodule

* `git clone https://github.com/web-eid/web-eid-app && cd web-eid-app`
* `git submodule set-url lib/libelectronic-id https://github.com/Muzosh/libelectronic-id && git submodule set-branch --branch feature-InfinitEID lib/libelectronic-id`
* `git submodule update --init --remote --recursive`
* **add line `{JsonWebSignatureAlgorithm::ES256, QCryptographicHash::Sha256},` to the map in `createSignature` function in `src/controller/command-handlers/authenticate.cpp`**
* **change the ATR according to your card** in `lib/libelectronic-id/src/electronic-id.cpp` in `SUPPORTED_ATRS` map

### Build modified Web-eID native application

* follow the build instructions in [official Web-eID repository](https://github.com/web-eid/web-eid-app#building-and-testing)
* builded app will work with InfinitEID
* for example, on MacOS you can replace the official Web-eID.app (installed from [here](https://web-eid.eu/)) by builded application from `./build/src/app/Web-eID.app`

# libelectronic-id

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png)

C++ library for performing cryptographic operations with electronic identification (eID) cards.

Currently supports Finnish, Estonian, Latvian and Lithuanian eID cards. Please
submit an issue if you want to request support for your country's eID card.

If possible, communicates with the eID card directly via PC/SC using APDUs
according to the card specification.

When APDU communication is not possible (e.g. Lithuanian eID), uses PKCS#11 and
requires the corresponding PKCS#11 module to be installed.

## Usage

Example how to automatically select and connect to a supported eID card, and
read the authentication certificate:

    const auto cardInfo = autoSelectSupportedCard();
    std::cout << "Reader " << cardInfo->reader().name << " has supported card "
                    << cardInfo->eid().name();

    const auto certificateBytes = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);

See more examples in [tests](tests).

## Building

    apt install build-essential pkg-config cmake libgtest-dev valgrind libpcsclite-dev
    sudo bash -c 'cd /usr/src/googletest && cmake . && cmake --build . --target install'

    cd build
    cmake .. # optionally with -DCMAKE_BUILD_TYPE=Debug
    cmake --build . # optionally with VERBOSE=1

## Testing

Build as described above, then run inside `build` directory:

    ctest # or 'valgrind --leak-check=full ctest'

`ctest` runs tests that use the _libscard-mock_ library to mock PC/SC API calls.

There are also integration tests that use the real operating system PC/SC
service, run them inside `build` directory with:

    ./libpcsc-cpp-test-integration

## Development guidelines

* Format code with `scripts/clang-format.sh` before committing
* See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
