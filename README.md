# Cyber-resilience-of-smart-PPE-an-algorithmic-method-for-preventing-occupational-injuries-
The proposed algorithm mitigates the risks of concealing real hazards and generating false alarms, ensuring that dispatch services receive reliable information for evacuation decision-making. 
# SipHash-2-4 for Smart Personal Protective Equipment (PPE)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![MicroPython](https://img.shields.io/badge/MicroPython-compatible-green.svg)](https://micropython.org/)

**Lightweight cryptographic data integrity for Industrial IoT safety systems**

> 📄 **Research Paper**: [Cyber resilience of smart PPE: an algorithmic method for preventing occupational injuries](https://github.com/yourusername/smart-ppe-integrity)  
> 👥 **Authors**: Olena Krainiuk, Yuriy Buts, Mykhailo Piksasov, Natalia Didenko, Boris Pokhodenko  
> 🏛️ **Affiliation**: Kharkiv National Automobile and Highway University, Ukraine

---

## 🎯 Problem Statement

Industrial Internet of Things (IIoT) safety devices — such as smart helmets, gas detectors, and wearable monitors — transmit **life-critical telemetry** over wireless channels. However:

- **Traditional cryptography** (TLS/DTLS, AES-CMAC) consumes 30-50% of battery capacity
- **No protection** leaves channels vulnerable to Man-in-the-Middle (MITM) attacks
- **False negatives** (hidden dangers) can be **fatal** in industrial environments

### The Dilemma
```
🔒 Strong Security (AES-256)  →  💀 Dead battery in 4 hours
🔓 No Security              →  ⚠️  Attacker can hide gas alarms
```

### Our Solution
**SipHash-2-4**: 15-20% battery life extension while maintaining 128-bit security.

---

## ✨ Features

- ⚡ **Ultra-fast**: ~340 µs per packet on ESP32 (3.5× faster than HMAC-SHA256)
- 🔋 **Energy-efficient**: 56 µJ per operation (2× less than AES-CMAC)
- 🧠 **Tiny footprint**: 32 bytes RAM (ARM Cortex-M compatible)
- 🛡️ **Cryptographically secure**: Resistant to hash flooding attacks
- 🏭 **Industry-compliant**: Meets IEC 62443 Level 0-1 requirements
- 📡 **Protocol-agnostic**: Works with MQTT, CoAP, LoRaWAN, BLE

---

## 📦 Installation

### For MicroPython (ESP32, Raspberry Pi Pico)
```bash
# Copy to device
ampy --port /dev/ttyUSB0 put siphash_iot.py
```

### For CPython (Development/Testing)
```bash
git clone https://github.com/yourusername/smart-ppe-integrity.git
cd smart-ppe-integrity
pip install -r requirements.txt  # Optional: for benchmarking
```

---

## 🚀 Quick Start

### Basic Usage
```python
from siphash_iot import siphash_24, create_signed_packet, verify_signed_packet
import os

# 1. Generate shared secret key (do this once, store securely)
key = os.urandom(16)  # 128-bit key

# 2. Worker's smart helmet creates signed packet
sensor_data = b'GAS:450ppm;TEMP:36.6;ALARM:CRITICAL'
packet = create_signed_packet(key, sensor_data)

# 3. Dispatch server verifies integrity
is_valid, payload = verify_signed_packet(key, packet)

if is_valid:
    print(f"✅ Authentic data: {payload}")
else:
    print("🚨 SECURITY ALERT: Data tampering detected!")
```

### Smart Helmet Example
```python
from example_usage import SmartHelmet, DispatchServer

# Initialize secure system
helmet = SmartHelmet(device_id=42, secret_key=shared_key)
server = DispatchServer(worker_keys={42: shared_key})

# Read sensors and transmit
telemetry = helmet.send_secure_telemetry({
    'gas_ppm': 450,
    'temperature': 36.6,
    'heart_rate': 78,
    'panic_button': False
})

# Server processes with integrity check
result = server.receive_telemetry(telemetry)
```

---

## 🧪 Performance Benchmarks

Run comprehensive tests:
```bash
python benchmark.py
```

### Results (ESP32 @ 240MHz, 64-byte packets)

| Algorithm       | Time (µs) | Energy (µJ) | RAM (bytes) | Speedup |
|-----------------|-----------|-------------|-------------|---------|
| **SipHash-2-4** | **340**   | **56**      | **32**      | 1.0×    |
| AES-CMAC        | 510       | 84          | 176         | 0.67×   |
| HMAC-SHA256     | 1240      | 205         | 256         | 0.27×   |

### Battery Life Impact
- **Transmission interval**: 10 seconds
- **Work shift**: 8 hours (2,880 packets)
- **SipHash battery usage**: 0.58%
- **Savings vs HMAC-SHA256**: ~1.2% → **~1 hour extended runtime**

---

## 🏗️ Architecture

### Packet Structure
```
┌─────────────────────────┬──────────────────────┐
│   Payload (variable)    │  SipHash Tag (8B)    │
│  Sensor readings, ID,   │  Integrity proof     │
│  timestamp, etc.        │  (64-bit MAC)        │
└─────────────────────────┴──────────────────────┘
```

### Security Properties
- **Authentication**: Verifies data origin (prevents spoofing)
- **Integrity**: Detects any modification (even single-bit flips)
- **Non-repudiation**: Tag can only be generated with secret key

### What SipHash Does NOT Provide
- ❌ **Confidentiality** (data is not encrypted)
- ❌ **Replay protection** (add timestamp/counter to payload)
- ❌ **Forward secrecy** (requires key rotation mechanism)

---

## 📊 Test Vectors

Validates against [official SipHash reference implementation](https://github.com/veorq/SipHash):

```bash
python tests/test_siphash.py
```

```
==========================================
TestSipHashOfficial
==========================================
  ✅ test_empty_message
  ✅ test_single_byte
  ✅ test_multibyte_messages
  ✅ test_eight_byte_block

Total: 25 tests | Passed: 25 | Failed: 0
```

---

## 🔒 Security Considerations

### Key Management
```python
# ❌ NEVER hardcode keys in production
key = b'0123456789ABCDEF'  # BAD!

# ✅ Use secure key derivation
import hashlib
master_secret = os.urandom(32)
device_key = hashlib.pbkdf2_hmac('sha256', master_secret, b'device42', 100000)[:16]
```

### Attack Scenarios

#### 1. Man-in-the-Middle (MITM)
**Threat**: Attacker intercepts packet and modifies critical gas reading from 450 ppm → 50 ppm.

**Protection**: 
```python
# Original: tag = SipHash(key, "GAS:450ppm")
# Tampered: tag ≠ SipHash(key, "GAS:50ppm")
# → Verification fails, alarm triggered
```

#### 2. Replay Attacks
**Threat**: Attacker records "all clear" packet and replays it during actual emergency.

**Mitigation** (not included in basic implementation):
```python
payload = struct.pack('<IH', timestamp, gas_ppm)  # Add timestamp
# Server: reject packets older than 30 seconds
```

#### 3. Side-Channel Attacks
- **Current implementation**: Best-effort constant-time operations
- **Production systems**: Use hardware AES acceleration when available
- **Key storage**: Use secure elements (ATECC608, TPM) for key storage

---

## 🛠️ Hardware Requirements

### Minimum Specifications
- **MCU**: ARM Cortex-M0+ or equivalent (16 MHz+)
- **RAM**: 128 KB (32 KB for state + buffer)
- **Flash**: 16 KB code + 16 KB key storage
- **Power**: 3.3V @ 50 mA active, <1 µA sleep mode

### Tested Platforms
| Device            | Status | Notes                          |
|-------------------|--------|--------------------------------|
| ESP32-WROOM-32    | ✅ Verified | Recommended                |
| ESP8266           | ✅ Verified | Limited RAM                |
| STM32L0 (Cortex-M0+) | ✅ Verified | Ultra-low power         |
| Arduino Uno (8-bit)  | ⚠️ Slow    | Use hardware AES if available |
| Raspberry Pi Pico    | ✅ Verified | Dual-core advantage    |

---

## 📚 API Reference

### Core Functions

#### `siphash_24(key: bytes, data: bytes) -> int`
Compute 64-bit authentication tag.

**Args**:
- `key`: 128-bit secret key (16 bytes)
- `data`: Message to authenticate (max 65535 bytes)

**Returns**: 64-bit integer tag

**Raises**: `ValueError` if key length ≠ 16 or data is empty

---

#### `verify_integrity(key: bytes, data: bytes, received_tag: int) -> bool`
Verify data authenticity.

**Returns**: `True` if valid, `False` if tampered/corrupted

---

#### `create_signed_packet(key: bytes, payload: bytes) -> bytes`
Create integrity-protected packet.

**Returns**: `payload + 8-byte tag`

---

#### `verify_signed_packet(key: bytes, packet: bytes) -> tuple`
Extract and verify payload.

**Returns**: `(is_valid: bool, payload: bytes | None)`

---

## 🔬 Research & Citations

If you use this code in academic research, please cite:

```bibtex
@article{krainiuk2025siphash,
  title={Cyber resilience of smart PPE: an algorithmic method for preventing occupational injuries},
  author={Krainiuk, Olena and Buts, Yuriy and Piksasov, Mykhailo and Didenko, Natalia and Pokhodenko, Boris},
  journal={[Journal Name]},
  year={2025},
  doi={10.xxxx/xxxxx}
}
```

### Related Work
- [SipHash: a fast short-input PRF](https://www.iacr.org/archive/fse2012/75490301/75490301.pdf) (Aumasson & Bernstein, 2012)
- [IEC 62443: Industrial communication networks - IT security](https://webstore.iec.ch/publication/7030)
- [NIST Lightweight Cryptography Standardization](https://csrc.nist.gov/projects/lightweight-cryptography)

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- [ ] Hardware acceleration (ARM NEON, RISC-V crypto extensions)
- [ ] Key rotation protocols
- [ ] Integration with MQTT-SN, CoAP-OSCORE
- [ ] Post-quantum alternatives (Sphincs+, Dilithium)

### Development Setup
```bash
git clone https://github.com/yourusername/smart-ppe-integrity.git
cd smart-ppe-integrity
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
pytest tests/ -v
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

**Commercial use**: Permitted with attribution  
**Liability**: No warranty. Use in production systems at your own risk.

---

## 🆘 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/smart-ppe-integrity/issues)
- **Email**: cyber@khadi.kharkov.ua
- **Research Group**: [Cybersecurity Department, KhADI](https://cyber.khadi.kharkov.ua)

---

## ⚠️ Safety Notice

This cryptographic implementation is provided for **research and educational purposes**. 

**Before deploying in life-critical systems**:
1. Conduct formal security audit
2. Implement key management system (KMS)
3. Add replay protection (timestamps/counters)
4. Test under electromagnetic interference (EMI) conditions
5. Comply with local industrial safety regulations (OSHA, IEC)

**Workers' lives depend on system reliability. Test thoroughly.**

---

## 📈 Roadmap

- [x] Core SipHash-2-4 implementation
- [x] Unit tests with official vectors
- [x] Performance benchmarks
- [ ] Key derivation functions (HKDF)
- [ ] MQTT/CoAP integration examples
- [ ] LoRaWAN packet format
- [ ] Web dashboard for real-time monitoring
- [ ] Android app for dispatch supervisors
- [ ] Formal verification (CBMC, cryptol)

---

**Made with ❤️ in Ukraine 🇺🇦**  
*For safer industrial workplaces worldwide.*
