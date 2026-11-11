"""add-profile-permission-stale-revision-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-profile-permission-stale-revision-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddProfilePermission with a stale revisionId is rejected as a conflict, not applied."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "stalerev")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    principal_account = ctx.client("sts").get_caller_identity()["Account"]
    signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)

    rev1 = signer.add_profile_permission(
        profileName=name,
        action="signer:GetSigningProfile",
        principal=principal_account,
        statementId="sim2real-stmt-a",
    )["revisionId"]

    code, message = _error(
        lambda: signer.add_profile_permission(
            profileName=name,
            action="signer:GetSigningProfile",
            principal=principal_account,
            statementId="sim2real-stmt-b",
            revisionId="stalerev0",
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = (
        "Specified revisionId (stalerev0) does not match the revisionId of the existing policy "
        f"({rev1})"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: statement B was never applied; policy is unchanged at rev1.
    listed = signer.list_profile_permissions(profileName=name)
    assert listed["revisionId"] == rev1, (
        f"expected revisionId to stay at {rev1!r} after the rejected call, got {listed['revisionId']!r}"
    )
    statement_ids = {p["statementId"] for p in listed["permissions"]}
    assert statement_ids == {"sim2real-stmt-a"}, (
        f"expected only sim2real-stmt-a to be present, got {statement_ids!r}"
    )

    # Restore: the identical call (same statementId) with the correct current revisionId succeeds.
    rev2 = signer.add_profile_permission(
        profileName=name,
        action="signer:GetSigningProfile",
        principal=principal_account,
        statementId="sim2real-stmt-b",
        revisionId=rev1,
    )["revisionId"]
    assert rev2 != rev1, f"expected revisionId to advance past {rev1!r}, got {rev2!r}"
    listed_after = signer.list_profile_permissions(profileName=name)
    statement_ids_after = {p["statementId"] for p in listed_after["permissions"]}
    assert statement_ids_after == {"sim2real-stmt-a", "sim2real-stmt-b"}, (
        f"expected sim2real-stmt-a and sim2real-stmt-b, got {statement_ids_after!r}"
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

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
