"""cancel-signing-profile-transitions-to-canceled."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cancel-signing-profile-transitions-to-canceled"
GROUP = "state"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelSigningProfile drives SigningProfileStatus from Active to Canceled."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "cancel")

    signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)
    initial_status = signer.get_signing_profile(profileName=name)["status"]
    assert initial_status == "Active", f"expected Active before cancel, got {initial_status!r}"

    signer.cancel_signing_profile(profileName=name)

    def probe():
        return signer.get_signing_profile(profileName=name)["status"]

    status = _poll_until(probe, lambda s: s == "Canceled", timeout_s=30.0, interval_s=2.0)
    assert status == "Canceled", f"expected Canceled after CancelSigningProfile, got {status!r}"


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
