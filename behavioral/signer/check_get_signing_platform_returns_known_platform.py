"""get-signing-platform-returns-known-platform."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-signing-platform-returns-known-platform"
GROUP = "control-plane"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSigningPlatform returns the full descriptor for a predefined AWS Signer platform."""
    signer = ctx.client("signer")
    resp = signer.get_signing_platform(platformId=LAMBDA_PLATFORM)

    assert resp["platformId"] == LAMBDA_PLATFORM, (
        f"expected platformId {LAMBDA_PLATFORM!r}, got {resp.get('platformId')!r}"
    )
    assert resp["displayName"] == "AWS Lambda", (
        f"expected displayName 'AWS Lambda', got {resp.get('displayName')!r}"
    )
    assert resp["partner"] == "AWSLambda", f"expected partner 'AWSLambda', got {resp.get('partner')!r}"
    assert resp["target"] == "SHA384-ECDSA", f"expected target 'SHA384-ECDSA', got {resp.get('target')!r}"
    assert resp["category"] == "AWS", f"expected category 'AWS', got {resp.get('category')!r}"
    assert resp["maxSizeInMB"] == 250, f"expected maxSizeInMB 250, got {resp.get('maxSizeInMB')!r}"
    assert resp["revocationSupported"] is True, (
        f"expected revocationSupported True, got {resp.get('revocationSupported')!r}"
    )

    signing_configuration = resp["signingConfiguration"]
    assert signing_configuration["hashAlgorithmOptions"]["allowedValues"] == ["SHA384"], (
        f"expected hash allowedValues ['SHA384'], got {signing_configuration['hashAlgorithmOptions']['allowedValues']!r}"
    )
    assert signing_configuration["encryptionAlgorithmOptions"]["allowedValues"] == ["ECDSA"], (
        f"expected encryption allowedValues ['ECDSA'], got {signing_configuration['encryptionAlgorithmOptions']['allowedValues']!r}"
    )
    assert resp["signingImageFormat"]["supportedFormats"] == ["JSONDetached"], (
        f"expected signingImageFormat supportedFormats ['JSONDetached'], got {resp['signingImageFormat']['supportedFormats']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
