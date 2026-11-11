"""put-signing-profile-duplicate-name-permanently-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-signing-profile-duplicate-name-permanently-rejected"
GROUP = "state"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutSigningProfile on a used name is rejected with ValidationException and the exact duplicate message,
    with or without a different signatureValidityPeriod and after the profile is Canceled; the original
    version is untouched and a new name still creates an Active profile.
    """
    signer = ctx.client("signer")
    name = _profile_name(ctx, "version")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))

    first = signer.put_signing_profile(
        profileName=name,
        platformId=LAMBDA_PLATFORM,
        tags={"sim2real-env": "behavioral"},
    )
    assert first["profileVersion"], f"expected a non-empty profileVersion, got {first!r}"

    # Identical re-invocation is rejected rather than silently succeeding.
    duplicate = f"Profile with name {name} already exists"
    dup_code, dup_message = _error(
        lambda: signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)
    )
    assert dup_code == "ValidationException", (
        f"expected ValidationException re-putting an existing profile name, got {dup_code!r}"
    )
    assert dup_message == duplicate, f"expected message {duplicate!r}, got {dup_message!r}"

    # Varying an overridable parameter does not change this: the name is still taken.
    override_code, override_message = _error(
        lambda: signer.put_signing_profile(
            profileName=name,
            platformId=LAMBDA_PLATFORM,
            signatureValidityPeriod={"value": 10, "type": "MONTHS"},
        )
    )
    assert override_code == "ValidationException", (
        f"expected ValidationException even with an overridden signatureValidityPeriod, "
        f"got {override_code!r}"
    )
    assert override_message == duplicate, (
        f"expected message {duplicate!r}, got {override_message!r}"
    )

    # The original version is untouched by the rejected attempts.
    latest = signer.get_signing_profile(profileName=name)
    assert latest["profileVersion"] == first["profileVersion"], (
        f"expected profileVersion to stay {first['profileVersion']!r}, got "
        f"{latest['profileVersion']!r}"
    )
    assert latest["profileVersionArn"] == first["profileVersionArn"], (
        f"expected profileVersionArn to stay {first['profileVersionArn']!r}, got "
        f"{latest['profileVersionArn']!r}"
    )

    # Canceling does not free the name either: PutSigningProfile against a Canceled
    # profile is still rejected — profile names are permanently reserved once used.
    signer.cancel_signing_profile(profileName=name)

    def probe():
        return signer.get_signing_profile(profileName=name)["status"]

    _poll_until(probe, lambda s: s == "Canceled", timeout_s=30.0, interval_s=2.0)

    canceled_code, canceled_message = _error(
        lambda: signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)
    )
    assert canceled_code == "ValidationException", (
        f"expected ValidationException re-putting a Canceled profile name, got {canceled_code!r}"
    )
    assert canceled_message == duplicate, (
        f"expected message {duplicate!r}, got {canceled_message!r}"
    )

    # The name stays permanently Canceled; a fresh, distinctly-named profile still works.
    status_after = signer.get_signing_profile(profileName=name)["status"]
    assert status_after == "Canceled", f"expected status Canceled, got {status_after!r}"
    control_name = _profile_name(ctx, "versionctrl")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, control_name))
    control = signer.put_signing_profile(
        profileName=control_name,
        platformId=LAMBDA_PLATFORM,
        tags={"sim2real-env": "behavioral"},
    )
    assert control["profileVersion"], f"expected a non-empty profileVersion, got {control!r}"

    # Terminal read is independent of the mutating PutSigningProfile call above.
    control_read = signer.get_signing_profile(profileName=control_name)
    assert control_read["profileVersion"] == control["profileVersion"], (
        f"expected the read-back profileVersion to be {control['profileVersion']!r}, got "
        f"{control_read['profileVersion']!r}"
    )
    assert control_read["status"] == "Active", (
        f"expected the fresh control profile to read back Active, got {control_read['status']!r}"
    )


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _cancel_quietly(signer, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses reads as an acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    import time

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

