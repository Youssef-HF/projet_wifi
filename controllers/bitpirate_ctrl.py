#!/usr/bin/env python3
"""
WauditBox v2.0 — controllers/bitpirate_ctrl.py
ESP32-Bit-Pirate controller via USB serial (/dev/esp32-bitpirate)
Controls: UART scan, SPI dump, I2C sniff, JTAG, BLE, 1-Wire
"""
# PLACEHOLDER — Full implementation in Phase 3
import serial
import time
import logging

BITPIRATE_PORT = "/dev/esp32-bitpirate"
BITPIRATE_BAUD = 115200

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bitpirate_ctrl")


class BitPirateController:
    def __init__(self, port: str = BITPIRATE_PORT, baud: int = BITPIRATE_BAUD):
        self.port = port
        self.baud = baud
        self.serial = None

    def connect(self) -> bool:
        try:
            self.serial = serial.Serial(self.port, self.baud, timeout=3)
            logger.info(f"Connected to ESP32-Bit-Pirate on {self.port}")
            return True
        except serial.SerialException as e:
            logger.error(f"Connection failed: {e}")
            return False

    def send_command(self, cmd: str) -> str:
        if not self.serial:
            raise RuntimeError("Not connected")
        self.serial.write(f"{cmd}\n".encode())
        time.sleep(1)
        return self.serial.read_all().decode(errors="ignore")

    def uart_scan(self) -> str:
        """Auto-scan UART ports on target."""
        return self.send_command("uart scan")

    def uart_bridge(self, baudrate: int = 115200) -> str:
        """Bridge to UART target at given baudrate."""
        return self.send_command(f"uart bridge {baudrate}")

    def spi_flash_dump(self, start: int = 0x000000, size: int = 0x100000) -> bytes:
        """Dump SPI flash memory."""
        cmd = f"spi flash dump {hex(start)} {hex(size)}"
        self.send_command(cmd)
        time.sleep(5)
        return self.serial.read_all()

    def i2c_scan(self) -> str:
        """Scan I2C bus for devices."""
        return self.send_command("i2c scan")

    def onewire_read(self) -> str:
        """Read 1-Wire device (iButton/DS18B20)."""
        self.send_command("1wire scan")
        return self.send_command("1wire read")

    def ble_scan(self) -> str:
        """Scan for BLE devices."""
        return self.send_command("ble scan")

    def disconnect(self):
        if self.serial:
            self.serial.close()


if __name__ == "__main__":
    bp = BitPirateController()
    if bp.connect():
        print(bp.uart_scan())
        bp.disconnect()
