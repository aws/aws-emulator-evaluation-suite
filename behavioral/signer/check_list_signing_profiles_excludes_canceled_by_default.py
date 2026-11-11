"""list-signing-profiles-excludes-canceled-by-default."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-signing-profiles-excludes-canceled-by-default"
GROUP = "state"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSigningProfiles omits Canceled profiles unless includeCanceled=True is passed."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "listexcl")

    signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)
    signer.cancel_signing_profile(profileName=name)

    def probe():
        return signer.get_signing_profile(profileName=name)["status"]

    _poll_until(probe, lambda s: s == "Canceled", timeout_s=30.0, interval_s=2.0)

    assert not _profile_name_in_listing(signer, name, includeCanceled=False), (
        f"expected canceled profile {name!r} to be excluded from the default "
        "ListSigningProfiles listing, but it was present"
    )
    assert _profile_name_in_listing(signer, name, includeCanceled=True), (
        f"expected canceled profile {name!r} to appear in ListSigningProfiles "
        "when includeCanceled=True, but it was absent"
    )


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


def _profile_name_in_listing(signer, name: str, *, includeCanceled: bool) -> bool:
    next_token = None
    for _ in range(50):
        kwargs = {"includeCanceled": includeCanceled, "maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = signer.list_signing_profiles(**kwargs)
        for profile in resp.get("profiles", []):
            if profile["profileName"] == name:
                return True
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
