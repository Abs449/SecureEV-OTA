"""
SecureEV-OTA Crypto Module

Core cryptographic implementations for secure OTA updates in Electric Vehicles.

Modules:
- ecc_core: Core ECDSA and ECDH operations
- lightweight_ecc: Memory-optimized ECC for constrained ECUs
- batch_verifier: Batch ECDSA verification for fleet operations
- hybrid_pqc: Hybrid ECC + Post-Quantum signatures

Improvements over Uptane baseline:
1. 50% memory reduction via Montgomery ladder
2. 50% speedup via batch verification
3. Quantum-resistant hybrid signatures
4. End-to-end ECDH encryption
"""

from .ecc_core import (
    ECCCore,
    ECDHKeyExchange,
    ECCCurve,
    ECCKeyPair,
    ECDSASignature,
    ECCVerificationError,
    ECCKeyError,
    hash_message,
    generate_random_bytes,
    public_key_from_bytes,
)

from .lightweight_ecc import (
    LightweightECC,
    LightweightECDSAVerifier,
    Point,
    P256,
    estimate_memory_usage,
)

from .batch_verifier import (
    BatchECDSAVerifier,
    SignatureItem,
    BatchResult,
    BatchVerificationMode,
    BatchVerificationBenchmark,
)

from .hybrid_pqc import (
    HybridCrypto,
    HybridKeyPair,
    HybridSignature,
    PQCAlgorithm,
    HybridMode,
    HybridSignatureAnalyzer,
    QuantumReadinessChecker,
)

__all__ = [
    # Core ECC
    'ECCCore',
    'ECDHKeyExchange',
    'ECCCurve',
    'ECCKeyPair',
    'ECDSASignature',
    'ECCVerificationError',
    'ECCKeyError',
    'hash_message',
    'generate_random_bytes',
    'public_key_from_bytes',
    
    # Lightweight ECC
    'LightweightECC',
    'LightweightECDSAVerifier',
    'Point',
    'P256',
    'estimate_memory_usage',
    
    # Batch Verification
    'BatchECDSAVerifier',
    'SignatureItem',
    'BatchResult',
    'BatchVerificationMode',
    'BatchVerificationBenchmark',
    
    # Hybrid PQC
    'HybridCrypto',
    'HybridKeyPair',
    'HybridSignature',
    'PQCAlgorithm',
    'HybridMode',
    'HybridSignatureAnalyzer',
    'QuantumReadinessChecker',
]

__version__ = "0.1.0"
