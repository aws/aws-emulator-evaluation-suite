"""create-identity-pool-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-identity-pool-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _pool_names(ci) -> set[str]:
    names: set[str] = set()
    paginator = ci.get_paginator("list_identity_pools")
    for page in paginator.paginate(MaxResults=60):
        for pool in page.get("IdentityPools", []):
            names.add(pool["IdentityPoolName"])
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIdentityPool rejects an IdentityPoolName containing characters outside [\\w\\s+=,.@-]+."""
    ci = ctx.client("cognito-identity")

    # Positive control: a well-formed name on the same call succeeds, so the rejection below
    # cannot be mistaken for CreateIdentityPool being broken or denied outright for this account.
    good_name = ctx.unique_name("sim2real_pool_ok_")
    control = ci.create_identity_pool(
        IdentityPoolName=good_name,
        AllowUnauthenticatedIdentities=True,
    )
    control_id = control["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=control_id))
    assert control["IdentityPoolName"] == good_name, (
        f"control create returned name {control['IdentityPoolName']!r}, expected {good_name!r}"
    )

    bad_name = ctx.unique_name("sim2real_pool_") + "#!$%"

    created_pool_id = {"value": None}

    def _create():
        resp = ci.create_identity_pool(
            IdentityPoolName=bad_name,
            AllowUnauthenticatedIdentities=True,
        )
        created_pool_id["value"] = resp.get("IdentityPoolId")
        if created_pool_id["value"]:
            # Defensive cleanup only; a faithful emulator never reaches here.
            ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=created_pool_id["value"]))
        return resp

    code, message = _error(_create)
    # Real AWS enforces the `^[\w\s+=,.@-]+$` pattern on IdentityPoolName at the request-shape
    # validation layer (before the CreateIdentityPool handler runs), which surfaces as the generic
    # ValidationException rather than the operation's modeled InvalidParameterException.
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"1 validation error detected: Value '{bad_name}' at 'identityPoolName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [\\w\\s+=,.@-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at the destination, through a different operation than the one that was
    # rejected: the malformed name must never have become visible, and the control pool must be.
    names_after = _pool_names(ci)
    assert bad_name not in names_after, (
        f"rejected pool name {bad_name!r} unexpectedly visible via ListIdentityPools"
    )
    assert good_name in names_after, (
        f"control pool name {good_name!r} missing from ListIdentityPools after a successful create"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
