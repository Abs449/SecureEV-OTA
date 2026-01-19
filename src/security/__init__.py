"""SecureEV-OTA Security Module"""

from .e2e_encryption import (
    E2EEncryption,
    EncryptedPackage,
    SessionKey,
    EncryptionMode,
    EncryptionError,
    DecryptionError,
    KeyExchangeError,
)

from .dos_protection import (
    DoSProtection,
    AdaptiveRateLimiter,
    ProgressiveTimeoutManager,
    MultiPathDelivery,
    UpdateRequest,
    UpdatePriority,
    RequestStatus,
    RateLimitConfig,
    TimeoutConfig,
    EndpointConfig,
    RateLimitExceeded,
    TimeoutExceeded,
    AllEndpointsFailed,
)

__all__ = [
    # E2E Encryption
    'E2EEncryption',
    'EncryptedPackage',
    'SessionKey',
    'EncryptionMode',
    'EncryptionError',
    'DecryptionError',
    'KeyExchangeError',
    
    # DoS Protection
    'DoSProtection',
    'AdaptiveRateLimiter',
    'ProgressiveTimeoutManager',
    'MultiPathDelivery',
    'UpdateRequest',
    'UpdatePriority',
    'RequestStatus',
    'RateLimitConfig',
    'TimeoutConfig',
    'EndpointConfig',
    'RateLimitExceeded',
    'TimeoutExceeded',
    'AllEndpointsFailed',
]

__version__ = "0.1.0"
