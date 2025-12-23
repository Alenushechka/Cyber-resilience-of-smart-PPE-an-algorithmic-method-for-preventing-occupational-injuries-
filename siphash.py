"""
SipHash-2-4 Implementation for IoT Safety Devices
==================================================
Lightweight cryptographic hash function optimized for
Smart Personal Protective Equipment (Smart PPE).

Author: Olena Krainiuk et al.
License: MIT
Paper: "Cyber resilience of smart PPE: an algorithmic method
        for preventing occupational injuries"
"""

import struct
import os

def siphash_24(key: bytes, data: bytes) -> int:
    """
    Compute SipHash-2-4 Message Authentication Code (MAC).

    Args:
        key: 128-bit secret key (exactly 16 bytes)
        data: Message to authenticate

    Returns:
        64-bit integrity tag as integer

    Example:
        >>> import os
        >>> # Використовуємо фіксований ключ для тесту
        >>> key = b'0123456789ABCDEF'
        >>> sensor_data = b'ID:05;GAS:450ppm;TEMP:36.6'
        >>> tag = siphash_24(key, sensor_data)
        >>> # Перевірка конкретного значення (розраховано для цього ключа і даних)
        >>> hex(tag)
        '0x57b291eda6f44bc1'
    """
    # Input validation
    if len(key) != 16:
        raise ValueError(f"Key must be exactly 16 bytes, got {len(key)}")
    if not data:
        raise ValueError("Data cannot be empty")

    # SipHash parameters
    c_rounds = 2
    d_rounds = 4

    # Initialize internal state
    v0 = 0x736f6d6570736575
    v1 = 0x646f72616e646f6d
    v2 = 0x6c7967656e657261
    v3 = 0x7465646279746573

    k0 = struct.unpack('<Q', key[0:8])[0]
    k1 = struct.unpack('<Q', key[8:16])[0]

    v0 ^= k0
    v1 ^= k1
    v2 ^= k0
    v3 ^= k1

    # === Compression Phase ===
    length = len(data)
    end_index = length - (length % 8)

    for i in range(0, end_index, 8):
        m = struct.unpack('<Q', data[i:i+8])[0]
        v3 ^= m
        for _ in range(c_rounds):
            v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
            v1 = ((v1 << 13) | (v1 >> 51)) & 0xFFFFFFFFFFFFFFFF
            v1 ^= v0
            v0 = ((v0 << 32) | (v0 >> 32)) & 0xFFFFFFFFFFFFFFFF

            v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
            v3 = ((v3 << 16) | (v3 >> 48)) & 0xFFFFFFFFFFFFFFFF
            v3 ^= v2

            v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
            v3 = ((v3 << 21) | (v3 >> 43)) & 0xFFFFFFFFFFFFFFFF
            v3 ^= v0

            v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
            v1 = ((v1 << 17) | (v1 >> 47)) & 0xFFFFFFFFFFFFFFFF
            v1 ^= v2
            v2 = ((v2 << 32) | (v2 >> 32)) & 0xFFFFFFFFFFFFFFFF
        v0 ^= m

    # === Process Remaining Bytes (Tail) ===
    last_block = length << 56
    tail_index = end_index
    while tail_index < length:
        last_block |= data[tail_index] << ((tail_index - end_index) * 8)
        tail_index += 1

    v3 ^= last_block
    for _ in range(c_rounds):
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = ((v1 << 13) | (v1 >> 51)) & 0xFFFFFFFFFFFFFFFF
        v1 ^= v0
        v0 = ((v0 << 32) | (v0 >> 32)) & 0xFFFFFFFFFFFFFFFF

        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = ((v3 << 16) | (v3 >> 48)) & 0xFFFFFFFFFFFFFFFF
        v3 ^= v2

        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = ((v3 << 21) | (v3 >> 43)) & 0xFFFFFFFFFFFFFFFF
        v3 ^= v0

        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = ((v1 << 17) | (v1 >> 47)) & 0xFFFFFFFFFFFFFFFF
        v1 ^= v2
        v2 = ((v2 << 32) | (v2 >> 32)) & 0xFFFFFFFFFFFFFFFF
    v0 ^= last_block

    # === Finalization Phase ===
    v2 ^= 0xFF
    for _ in range(d_rounds):
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = ((v1 << 13) | (v1 >> 51)) & 0xFFFFFFFFFFFFFFFF
        v1 ^= v0
        v0 = ((v0 << 32) | (v0 >> 32)) & 0xFFFFFFFFFFFFFFFF

        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = ((v3 << 16) | (v3 >> 48)) & 0xFFFFFFFFFFFFFFFF
        v3 ^= v2

        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = ((v3 << 21) | (v3 >> 43)) & 0xFFFFFFFFFFFFFFFF
        v3 ^= v0

        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = ((v1 << 17) | (v1 >> 47)) & 0xFFFFFFFFFFFFFFFF
        v1 ^= v2
        v2 = ((v2 << 32) | (v2 >> 32)) & 0xFFFFFFFFFFFFFFFF

    return (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFFFFFFFFFF


def verify_integrity(key: bytes, data: bytes, received_tag: int) -> bool:
    """
    Verify data integrity against received authentication tag.

    Example:
        >>> key = b'0123456789ABCDEF'
        >>> data = b'SENSOR_DATA'
        >>> # Розраховуємо правильний тег прямо тут, щоб тест був надійним
        >>> expected_tag = siphash_24(key, data)
        >>> verify_integrity(key, data, expected_tag)
        True
        >>> verify_integrity(key, b'MODIFIED_DATA', expected_tag)
        False
    """
    try:
        computed_tag = siphash_24(key, data)
        return computed_tag == received_tag
    except ValueError:
        return False


def create_signed_packet(key: bytes, payload: bytes) -> bytes:
    """
    Create integrity-protected packet.

    Example:
        >>> import struct
        >>> key = b'0123456789ABCDEF'
        >>> telemetry = b'GAS:450ppm'
        >>> packet = create_signed_packet(key, telemetry)
        >>> len(packet)
        18
    """
    tag = siphash_24(key, payload)
    return payload + struct.pack('<Q', tag)


def verify_signed_packet(key: bytes, packet: bytes) -> tuple:
    """
    Verify and extract payload from signed packet.

    Example:
        >>> key = b'0123456789ABCDEF'
        >>> # Створюємо валідний пакет
        >>> packet = create_signed_packet(key, b'DATA')
        >>> is_valid, payload = verify_signed_packet(key, packet)
        >>> is_valid
        True
        >>> payload
        b'DATA'
    """
    if len(packet) < 9:
        return False, None

    payload = packet[:-8]
    received_tag = struct.unpack('<Q', packet[-8:])[0]

    is_valid = verify_integrity(key, payload, received_tag)

    return (is_valid, payload if is_valid else None)

# --- Блок запуску для ручної перевірки ---
if __name__ == "__main__":
    print("--- Running Manual Tests ---")
    test_key = b'0123456789ABCDEF'
    test_data = b'CRITICAL_ALARM:LEVEL_5'
    
    print(f"Key: {test_key}")
    print(f"Data: {test_data}")
    
    # 1. Генерація тегу
    tag = siphash_24(test_key, test_data)
    print(f"SipHash Tag: {hex(tag)}")
    
    # 2. Перевірка
    is_valid = verify_integrity(test_key, test_data, tag)
    print(f"Verification Result: {is_valid}")
    
    # 3. Симуляція атаки
    print("\n--- Simulating Attack ---")
    fake_data = b'NORMAL_STATUS:LEVEL_0'
    is_fake_valid = verify_integrity(test_key, fake_data, tag)
    print(f"Attack Data: {fake_data}")
    print(f"Attack Verification: {is_fake_valid} (Should be False)")