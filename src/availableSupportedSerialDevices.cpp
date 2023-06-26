/*
 * Copyright (c) 2023 Petr Muzikant
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

#include "electronic-id/electronic-id.hpp"
#include "serial-cpp/serial-cpp.hpp"
#include <QtSerialPort/qserialport.h>
#include <QtSerialPort/qserialportinfo.h>
#include <QDebug>

namespace
{

using namespace electronic_id;

inline SerialDeviceInfo::ptr getSerialDeviceInfo(const serial_cpp::SerialPortHandler _portHandler)
{
    auto eid = getSerialDeviceElectronicID(_portHandler);
    return std::make_shared<SerialDeviceInfo>(eid, _portHandler);
}

inline QList<QSerialPortInfo> getAvailableSerialPorts()
{
    // QSerialPortInfo::availablePorts() should be OS independent
    QList<QSerialPortInfo> ports = QSerialPortInfo::availablePorts();

    // Filter out non communication units (cu)
    ports.erase(std::remove_if(ports.begin(), ports.end(),
                               [](const QSerialPortInfo& portInfo) {
                                   return !portInfo.portName().startsWith("cu.");
                               }),
                ports.end());

    // If there is serialDeviceInfoOpenedByWebEid, but its port is not available anymore,
    // it was probably disconnected (thus closed) -> remove it from the
    // serialDeviceInfosOpenedByWebEid list.
    serialDeviceInfosOpenedByWebEid.remove_if(
        [&](const SerialDeviceInfo::ptr& deviceInfoOpenedByWebEid) {
            auto foundPortInfo =
                std::find_if(ports.begin(), ports.end(), [&](const QSerialPortInfo& portInfo) {
                    return deviceInfoOpenedByWebEid->eidContainerInfoName()
                        == portInfo.portName().toStdString();
                });
            // if foundPortInfo == ports.end(), the deviceInfoOpenedByWebEid is not in the new
            // available ports list, remove it
            return foundPortInfo == ports.end();
        });

    return ports;
}

} // namespace

namespace electronic_id
{

std::vector<SerialDeviceInfo::ptr> availableSupportedSerialDevices()
{
    std::vector<SerialDeviceInfo::ptr> serialDeviceInfosToReturn;
    std::unique_ptr<serial_cpp::SerialPortHandler> portHandler;

    // Get available serial ports
    QList<QSerialPortInfo> ports = getAvailableSerialPorts();

    // Try to open all available serial ports and check if they are supported
    for (const QSerialPortInfo& portInfo : ports) {
        try {
            // SeriaPortHandler constructor temporarily opens the port to get the device status and
            // fills all of its attributes
            portHandler.reset(new serial_cpp::SerialPortHandler(portInfo));
        } catch (const serial_cpp::SDevicePortNotOpenedError& ex) {
            // If the port is already opened by WebEid, it can't be opened again, but we want to
            // return it:

            // Check if the device is already opened by Web-eID
            auto foundDeviceInfo = std::find_if(
                serialDeviceInfosOpenedByWebEid.begin(), serialDeviceInfosOpenedByWebEid.end(),
                [&](const SerialDeviceInfo::ptr& deviceInfo) {
                    return deviceInfo->eidContainerInfoName() == portInfo.portName().toStdString();
                });
            if (foundDeviceInfo != serialDeviceInfosOpenedByWebEid.end()) {
                // If found, add it to the return list
                serialDeviceInfosToReturn.push_back(*foundDeviceInfo);
                continue;
            }

            // If device can't be opened (probably because it is opened by some completely other
            // application), do nothing, the serial device is probably used for something completely
            // else.
            // qInfo() << "Device " << portInfo.portName()
            //         << "could not be opened and is not previously opened by Web-eID. Reason: "
            //         << ex.what();
            continue;
        } catch (const serial_cpp::SDeviceTimeoutError&) {
            // Do nothing, the serial device is probably used for something completely else.
            // It didn't respond with the 0x9000 to the GET_STATUS command.
            // qInfo() << "Device " << portInfo.portName() << "timed out when asking for STATUS";
            continue;
        } catch (const serial_cpp::SDeviceDataFormatError&) {
            SERIAL_CPP_THROW(serial_cpp::SDeviceError,
                             "Device recognized, but could not parse status.");
        } catch (const serial_cpp::SDeviceCommunicationError&) {
            SERIAL_CPP_THROW(serial_cpp::SDeviceError,
                             "Device recognized, but could not receive data.");
        }

        // If portHandler inicialized successfully and device is supported, add it to the return
        // list
        if (portHandler && isSerialDeviceSupported(portHandler->serialID)) {
            // Get the SerialDeviceInfo::ptr
            SerialDeviceInfo::ptr selectedSerialDeviceInfo = getSerialDeviceInfo(*portHandler);
            // Add it to the global list of device opened by Web-eID
            serialDeviceInfosOpenedByWebEid.push_back(selectedSerialDeviceInfo);
            // Also add it to the returned result
            serialDeviceInfosToReturn.push_back(selectedSerialDeviceInfo);
        }
    }

    if (serialDeviceInfosToReturn.empty()) {
        throw AutoSelectFailed(AutoSelectFailed::Reason::NO_SUPPORTED_SERIAL_DEVICES);
    }

    return serialDeviceInfosToReturn;
}

} // namespace electronic_id
