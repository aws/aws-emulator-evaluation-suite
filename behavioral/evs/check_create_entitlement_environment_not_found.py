"""create-entitlement-environment-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-entitlement-environment-not-found"
GROUP = "errors"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEntitlement against a well-formed but nonexistent environmentId and
    connectorId raises ResourceNotFoundException, and no entitlement is created
    anywhere."""
    evs = ctx.client("evs")

    # Positive control: EVS is reachable and IAM auth is healthy independent of the
    # not-found rejection below -- otherwise "everything is denied" would look
    # identical to "this specific pair does not exist".
    before = evs.list_environments()["environmentSummaries"]

    code, message = _error(
        lambda: evs.create_entitlement(
            environmentId="env-0000000000",
            connectorId="cnctr-0000000000",
            entitlementType="WINDOWS_SERVER",
            vmIds=["vm-1234567"],
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}: {message}"
    assert message == "Environment env-0000000000 was not found", f"unexpected message {message!r}"

    after = evs.list_environments()["environmentSummaries"]
    assert after == before, (
        f"CreateEntitlement was refused but the environment list changed: {before!r} -> {after!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
