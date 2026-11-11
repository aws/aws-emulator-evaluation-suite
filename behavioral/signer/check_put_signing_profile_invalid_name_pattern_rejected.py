"""put-signing-profile-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-signing-profile-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutSigningProfile rejects a profileName violating ^[a-zA-Z0-9_]{2,}$; valid names work."""
    signer = ctx.client("signer")
    invalid_name = "sim2real-bad-name!"

    code, message = _error(
        lambda: signer.put_signing_profile(profileName=invalid_name, platformId=LAMBDA_PLATFORM)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Profile name must contain only alphanumeric characters and underscore."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected name itself never appears in the list at the destination
    # (a fabricated stand-in name here would pass regardless of what the target actually did).
    listed_names = _list_all_profile_names(signer)
    assert invalid_name not in listed_names, (
        f"rejected profileName {invalid_name!r} unexpectedly present in list_signing_profiles"
    )

    # Positive control: a name that satisfies the pattern is accepted.
    valid_name = _profile_name(ctx, "validname")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, valid_name))
    control_resp = signer.put_signing_profile(
        profileName=valid_name, platformId=LAMBDA_PLATFORM, tags={"sim2real-env": "behavioral"}
    )
    assert control_resp["arn"], f"expected arn in control response, got {control_resp!r}"

    # Terminal read is independent, at the destination, through a different operation.
    described = signer.get_signing_profile(profileName=valid_name)
    assert described["status"] == "Active", f"expected Active, got {described['status']!r}"
    assert described["arn"] == control_resp["arn"], (
        f"expected {control_resp['arn']!r}, got {described['arn']!r}"
    )


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _list_all_profile_names(signer) -> set[str]:
    names: set[str] = set()
    kwargs: dict = {}
    while True:
        resp = signer.list_signing_profiles(**kwargs)
        names.update(p["profileName"] for p in resp.get("profiles", []))
        token = resp.get("nextToken")
        if not token:
            return names
        kwargs["nextToken"] = token


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

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
