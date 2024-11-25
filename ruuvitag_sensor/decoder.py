import base64
import logging
import math
import struct
from typing import Optional, Tuple, Union

from ruuvitag_sensor.ruuvi_types import ByteData, SensorData3, SensorData5, SensorDataUrl, SensorData8

from Crypto.Cipher import AES

log = logging.getLogger(__name__)


def get_decoder(data_type: int):
    """
    Get correct decoder for Data Type.

    Returns:
        object: Data decoder
    """
    if data_type == 2:
        log.warning("DATA TYPE 2 IS OBSOLETE. UPDATE YOUR TAG")
        # https://github.com/ruuvi/ruuvi-sensor-protocols/blob/master/dataformat_04.md
        return UrlDecoder()
    if data_type == 4:
        log.warning("DATA TYPE 4 IS OBSOLETE. UPDATE YOUR TAG")
        # https://github.com/ruuvi/ruuvi-sensor-protocols/blob/master/dataformat_04.md
        return UrlDecoder()
    if data_type == 3:
        log.warning("DATA TYPE 3 IS DEPRECATED - UPDATE YOUR TAG")
        # https://github.com/ruuvi/ruuvi-sensor-protocols/blob/master/dataformat_03.md
        return Df3Decoder()
    
    if data_type == 0xFA:
        log.warning("DATA TYPE FA has no decryption!")
        return DfFADecoder()
    
    if data_type == 8:
        log.warning("DATA TYPE 8 not supported!")
        return Df8Decoder()
    
    return Df5Decoder()


def parse_mac(data_format: int, payload_mac: str) -> str:
    """
    Data format 5 payload contains MAC-address in format e.g. e62eb92e73e5

    Returns:
        string: MAC separated and in upper case e.g. E6:2E:B9:2E:73:E5
    """
    if data_format == 5:
        return ":".join(payload_mac[i : i + 2] for i in range(0, 12, 2)).upper()
    return payload_mac


class UrlDecoder:
    """
    Decodes data from RuuviTag url
    Protocol specification:
    https://github.com/ruuvi/ruuvi-sensor-protocols

    Decoder operations are ported from:
    https://github.com/ruuvi/sensor-protocol-for-eddystone-url/blob/master/index.html

    0:   uint8_t     format;          // (0x02 = realtime sensor readings)
    1:   uint8_t     humidity;        // one lsb is 0.5%
    2-3: uint16_t    temperature;     // Signed 8.8 fixed-point notation.
    4-5: uint16_t    pressure;        // (-50kPa)
    6-7: uint16_t    time;            // seconds (now from reset)

    The bytes for temperature, pressure and time are swapped during the encoding
    """

    def _get_temperature(self, decoded: bytearray) -> float:
        """Return temperature in celsius"""
        temp = (decoded[2] & 127) + decoded[3] / 100
        sign = (decoded[2] >> 7) & 1
        if sign == 0:
            return round(temp, 2)
        return round(-1 * temp, 2)

    def _get_humidity(self, decoded: bytearray) -> float:
        """Return humidity %"""
        return decoded[1] * 0.5

    def _get_pressure(self, decoded: bytearray) -> float:
        """Return air pressure hPa"""
        pressure = ((decoded[4] << 8) + decoded[5]) + 50000
        return pressure / 100

    def decode_data(self, encoded) -> Optional[SensorDataUrl]:
        """
        Decode sensor data.

        Returns:
            dict: Sensor values
        """
        try:
            identifier = None
            data_format = 2
            if len(encoded) > 8:
                data_format = 4
                identifier = encoded[8:]
                encoded = encoded[:8]
            decoded = bytearray(base64.b64decode(encoded, "-_"))  # type: ignore
            return {
                "data_format": data_format,
                "temperature": self._get_temperature(decoded),
                "humidity": self._get_humidity(decoded),
                "pressure": self._get_pressure(decoded),
                "identifier": identifier,
            }
        except Exception:
            log.exception("Encoded value: %s not valid", encoded)
            return None


class Df3Decoder:
    """
    Decodes data from RuuviTag with Data Format 3
    Protocol specification:
    https://github.com/ruuvi/ruuvi-sensor-protocols
    """

    def _get_temperature(self, data: ByteData) -> float:
        """Return temperature in celsius"""

        # The temperature is in two fields, one for the integer part,
        # one for the fraction
        #
        # The integer part was decoded as a signed two's complement number,
        # but this isn't how it's really stored. The MSB is a sign, the lower
        # 7 bits are the unsigned temperature value.
        #
        # To convert from the decoded value we have to add 128 and then negate,
        # if the decoded value was negative
        frac = data[3] / 100
        if data[2] < 0:
            return -(data[2] + 128 + frac)

        return data[2] + frac

    def _get_humidity(self, data: ByteData) -> float:
        """Return humidity %"""
        return data[1] * 0.5

    def _get_pressure(self, data: ByteData) -> float:
        """Return air pressure hPa"""
        return (data[4] + 50000) / 100

    def _get_acceleration(self, data: ByteData) -> Tuple[int, int, int]:
        """Return acceleration mG"""
        return data[5:8]  # type: ignore

    def _get_battery(self, data: ByteData) -> int:
        """Return battery mV"""
        return data[8]

    def decode_data(self, data: str) -> Optional[SensorData3]:
        """
        Decode sensor data.

        Returns:
            dict: Sensor values
        """
        try:
            byte_data: ByteData = struct.unpack(">BBbBHhhhH", bytearray.fromhex(data[:28]))
            acc_x, acc_y, acc_z = self._get_acceleration(byte_data)
            return {
                "data_format": 3,
                "humidity": self._get_humidity(byte_data),
                "temperature": self._get_temperature(byte_data),
                "pressure": self._get_pressure(byte_data),
                "acceleration": math.sqrt(acc_x * acc_x + acc_y * acc_y + acc_z * acc_z),
                "acceleration_x": acc_x,
                "acceleration_y": acc_y,
                "acceleration_z": acc_z,
                "battery": self._get_battery(byte_data),
            }
        except Exception:
            log.exception("Value: %s not valid", data)
            return None

class DfFADecoder:
    """
    Decodes data from RuuviTag with Data Format FA
    Protocol specification:
    https://github.com/ruuvi/ruuvi-sensor-protocols
    """

    def _get_temperature(self, data: ByteData) -> float:
        """Return temperature in celsius"""

        # The temperature is in two fields, one for the integer part,
        # one for the fraction
        #
        # The integer part was decoded as a signed two's complement number,
        # but this isn't how it's really stored. The MSB is a sign, the lower
        # 7 bits are the unsigned temperature value.
        #
        # To convert from the decoded value we have to add 128 and then negate,
        # if the decoded value was negative
        frac = data[3] / 100
        if data[2] < 0:
            return -(data[2] + 128 + frac)

        return data[2] + frac

    def _get_humidity(self, data: ByteData) -> float:
        """Return humidity %"""
        return data[1] * 0.5

    def _get_pressure(self, data: ByteData) -> float:
        """Return air pressure hPa"""
        return (data[4] + 50000) / 100

    def _get_acceleration(self, data: ByteData) -> Tuple[int, int, int]:
        """Return acceleration mG"""
        return data[5:8]  # type: ignore

    def _get_battery(self, data: ByteData) -> int:
        """Return battery mV"""
        return data[8]
 
    def _get_mac(self, data: ByteData):
        return "".join(f"{x:02x}" for x in data[9:])

    def decode_data(self, data: str) -> Optional[SensorData3]:
        """
        Decode sensor data.

        Returns:
            dict: Sensor values
        """
        try:
            byte_data: ByteData = struct.unpack(">BBbBHhhhH", bytearray.fromhex(data[:28]))
            acc_x, acc_y, acc_z = self._get_acceleration(byte_data)
            return {
                "data_format": 0xFA,
                "humidity": self._get_humidity(byte_data),
                "temperature": self._get_temperature(byte_data),
                "pressure": self._get_pressure(byte_data),
                "acceleration": math.sqrt(acc_x * acc_x + acc_y * acc_y + acc_z * acc_z),
                "acceleration_x": acc_x,
                "acceleration_y": acc_y,
                "acceleration_z": acc_z,
                "battery": self._get_battery(byte_data),
                #"mac": self._get_mac(byte_data),
            }
        except Exception:
            log.exception("Value: %s not valid", data)
            return None

class Df5Decoder:
    """
    Decodes data from RuuviTag with Data Format 5
    Protocol specification:
    https://github.com/ruuvi/ruuvi-sensor-protocols
    """

    def _get_temperature(self, data: ByteData) -> Optional[float]:
        """Return temperature in celsius"""
        if data[1] == -32768:
            return None

        return round(data[1] / 200, 2)

    def _get_humidity(self, data: ByteData) -> Optional[float]:
        """Return humidity %"""
        if data[2] == 65535:
            return None

        return round(data[2] / 400, 2)

    def _get_pressure(self, data: ByteData) -> Optional[float]:
        """Return air pressure hPa"""
        if data[3] == 0xFFFF:
            return None

        return round((data[3] + 50000) / 100, 2)

    def _get_acceleration(self, data: ByteData) -> Union[Tuple[None, None, None], Tuple[int, int, int]]:
        """Return acceleration mG"""
        if data[4] == -32768 or data[5] == -32768 or data[6] == -32768:
            return (None, None, None)

        return data[4:7]  # type: ignore

    def _get_powerinfo(self, data: ByteData) -> Tuple[int, int]:
        """Return battery voltage and tx power"""
        battery_voltage = data[7] >> 5
        tx_power = data[7] & 0x001F

        return (battery_voltage, tx_power)

    def _get_battery(self, data: ByteData) -> Optional[int]:
        """Return battery mV"""
        battery_voltage = self._get_powerinfo(data)[0]
        if battery_voltage == 0b11111111111:
            return None

        return battery_voltage + 1600

    def _get_txpower(self, data: ByteData) -> Optional[int]:
        """Return transmit power"""
        tx_power = self._get_powerinfo(data)[1]
        if tx_power == 0b11111:
            return None

        return -40 + (tx_power * 2)

    def _get_movementcounter(self, data: ByteData) -> int:
        return data[8]

    def _get_measurementsequencenumber(self, data: ByteData) -> int:
        return data[9]

    def _get_mac(self, data: ByteData):
        return "".join(f"{x:02x}" for x in data[10:])

    def _get_rssi(self, rssi_byte: str) -> int:
        """Return RSSI value in dBm."""
        rssi = int(rssi_byte, 16)
        if rssi > 127:
            rssi = (256 - rssi) * -1
        return rssi

    def decode_data(self, data: str) -> Optional[SensorData5]:
        """
        Decode sensor data.

        Returns:
            dict: Sensor values
        """
        try:
            byte_data: ByteData = struct.unpack(">BhHHhhhHBH6B", bytearray.fromhex(data[:48]))
            rssi = data[48:]

            acc_x, acc_y, acc_z = self._get_acceleration(byte_data)
            acc = math.sqrt(acc_x * acc_x + acc_y * acc_y + acc_z * acc_z) if acc_x and acc_y and acc_z else None

            # NOTE: Value parsing methods can return None, but it shouldn't happen with the
            # production firmware. Therefore properties are not optional on SensorData-type.

            return {
                "data_format": 5,
                "humidity": self._get_humidity(byte_data),  # type: ignore
                "temperature": self._get_temperature(byte_data),  # type: ignore
                "pressure": self._get_pressure(byte_data),  # type: ignore
                "acceleration": acc,  # type: ignore
                "acceleration_x": acc_x,  # type: ignore
                "acceleration_y": acc_y,  # type: ignore
                "acceleration_z": acc_z,  # type: ignore
                "tx_power": self._get_txpower(byte_data),  # type: ignore
                "battery": self._get_battery(byte_data),  # type: ignore
                "movement_counter": self._get_movementcounter(byte_data),
                "measurement_sequence_number": self._get_measurementsequencenumber(byte_data),
                "mac": self._get_mac(byte_data),
                "rssi": self._get_rssi(rssi) if rssi else None,
            }
        except Exception:
            log.exception("Value: %s not valid", data)
            return None   

class Df8Decoder:
    """
    Decodes data from RuuviTag with Data Format 8
    Protocol specification:
    https://github.com/ruuvi/ruuvi-sensor-protocols
    """

    def _get_temperature(self, data: ByteData) -> Optional[float]:
        """Return temperature in celsius"""
        if data[0] == -32768:
            return None

        return round(data[0] / 200, 2)

    def _get_humidity(self, data: ByteData) -> Optional[float]:
        """Return humidity %"""
        if data[1] == 65535:
            return None

        return round(data[1] / 400, 2)

    def _get_pressure(self, data: ByteData) -> Optional[float]:
        """Return air pressure hPa"""
        if data[2] == 0xFFFF:
            return None

        return round((data[2] + 50000) / 100, 2)

    def _get_powerinfo(self, data: ByteData) -> Tuple[int, int]:
        """Return battery voltage and tx power"""
        battery_voltage = data[3] >> 5
        tx_power = data[3] & 0x001F

        return (battery_voltage, tx_power)

    def _get_battery(self, data: ByteData) -> Optional[int]:
        """Return battery mV"""
        battery_voltage = self._get_powerinfo(data)[0]
        if battery_voltage == 0b11111111111:
            return None

        return battery_voltage + 1600

    def _get_txpower(self, data: ByteData) -> Optional[int]:
        """Return transmit power"""
        tx_power = self._get_powerinfo(data)[1]
        if tx_power == 0b11111:
            return None

        return -40 + (tx_power * 2)

    def _get_movementcounter(self, data: ByteData) -> int:
        return data[4]

    def _get_measurementsequencenumber(self, data: ByteData) -> int:
        return data[5]

    def _get_rssi(self, rssi_byte: str) -> int:
        """Return RSSI value in dBm."""
        rssi = int(rssi_byte, 16)
        if rssi > 127:
            rssi = (256 - rssi) * -1
        return rssi
    
    def _generate_key( self, app_key, device_id):

        # Convert app_key from hex string to a list of integer bytes
        app_key_bytes = [int(app_key[i:i+2], 16) for i in range(0, len(app_key), 2)]
        
        # Convert device_id from hex string to an integer
        device_id_int = int(device_id, 16)
        
        # Copy the converted app_key
        key = bytearray(app_key_bytes)

        # Apply XOR operation with device ID bytes
        for i in range(8):
            # Extract the relevant byte from device_id and XOR it with key[i]
            key[i] ^= (device_id_int >> (i * 8)) & 0xFF

        return key
    
    def _decrypt_data(self, key, encrypted_data):
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data

    def decode_data(self, data: str) -> Optional[SensorData8]:
        """
        Decode sensor data.

        Returns:
            dict: Sensor values
        """
        try:
            app_key = "5275757669436f6d5275757669546167"
            deviceID = "87D2D464E8B90162"

            key = self._generate_key(app_key, deviceID)

            encrypted = data[2:34]
            decrypted = self._decrypt_data(key, bytes.fromhex(encrypted))

            byte_data: ByteData = struct.unpack(">h5H4B", decrypted)
            mac = data[36:48]
            rssi = data[48:]

            return {
                "data_format": 8,
                "humidity": self._get_humidity(byte_data),  # type: ignore
                "temperature": self._get_temperature(byte_data),  # type: ignore
                "pressure": self._get_pressure(byte_data),  # type: ignore
                "tx_power": self._get_txpower(byte_data),  # type: ignore
                "battery": self._get_battery(byte_data),  # type: ignore
                "movement_counter": self._get_movementcounter(byte_data),
                "measurement_sequence_number": self._get_measurementsequencenumber(byte_data),
                "mac": mac,
                "rssi": self._get_rssi(rssi) if rssi else None,
            }
        except Exception:
            log.exception("Value: %s not valid", data)
            return None
