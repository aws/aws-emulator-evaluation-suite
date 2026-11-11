"""add-profile-permission-add-and-remove-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-profile-permission-add-and-remove-round-trip"
GROUP = "state"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddProfilePermission/RemoveProfilePermission mutate the policy and advance revisionId."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "permrt")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    principal_account = ctx.client("sts").get_caller_identity()["Account"]

    signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)

    add_resp = signer.add_profile_permission(
        profileName=name,
        action="signer:GetSigningProfile",
        principal=principal_account,
        statementId="sim2real-stmt-a",
    )
    rev1 = add_resp["revisionId"]

    listed = signer.list_profile_permissions(profileName=name)
    assert listed["revisionId"] == rev1, (
        f"expected ListProfilePermissions revisionId {rev1!r} after add, got {listed['revisionId']!r}"
    )
    statements = {p["statementId"]: p for p in listed["permissions"]}
    assert statements["sim2real-stmt-a"]["principal"] == principal_account, (
        f"expected principal {principal_account!r} on sim2real-stmt-a, "
        f"got {statements['sim2real-stmt-a']['principal']!r}"
    )
    assert statements["sim2real-stmt-a"]["action"] == "signer:GetSigningProfile", (
        "expected action signer:GetSigningProfile on sim2real-stmt-a, "
        f"got {statements['sim2real-stmt-a']['action']!r}"
    )

    # RemoveProfilePermission's response carries no revisionId even though the API model
    # lists it as an optional output member, so there is nothing here to compare against rev1.
    signer.remove_profile_permission(
        profileName=name, revisionId=rev1, statementId="sim2real-stmt-a"
    )

    # Once the last statement is removed, ListProfilePermissions has nothing to return and
    # raises ResourceNotFoundException rather than an empty list — this is the empirical
    # AWS behavior, not a bug in the check.
    from botocore.exceptions import ClientError

    try:
        listed_after = signer.list_profile_permissions(profileName=name)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            "expected ResourceNotFoundException for an empty policy, "
            f"got {exc.response['Error']['Code']!r}"
        )
        expected = f"No policies associated with profile {name}"
        message = exc.response["Error"].get("Message")
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"expected ResourceNotFoundException for an empty policy, got {listed_after!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
