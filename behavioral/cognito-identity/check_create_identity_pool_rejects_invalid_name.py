"""create-identity-pool-rejects-invalid-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-identity-pool-rejects-invalid-name"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive guard: CreateIdentityPool rejects names with disallowed characters,
    the pool never appears in ListIdentityPools, and an otherwise-identical valid name still
    succeeds -- proving the rejection targets the disallowed characters, not every call."""
    ci = ctx.client("cognito-identity")

    invalid_name = "!!!invalid###name???"
    err, message = _error(
        lambda: ci.create_identity_pool(
            IdentityPoolName=invalid_name,
            AllowUnauthenticatedIdentities=True,
        )
    )
    assert err == "ValidationException", (
        f"expected ValidationException for malformed IdentityPoolName, got {err}"
    )
    expected = (
        f"1 validation error detected: Value '{invalid_name}' at 'identityPoolName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [\\w\\s+=,.@-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    found = False
    next_token = None
    while True:
        kwargs = {"MaxResults": 60}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ci.list_identity_pools(**kwargs)
        if any(p.get("IdentityPoolName") == invalid_name for p in resp.get("IdentityPools", [])):
            found = True
        next_token = resp.get("NextToken")
        if not next_token or found:
            break
    assert not found, f"a pool named {invalid_name!r} should never have been created, but it lists"

    valid_name = ctx.unique_name("sim2real_pool_")
    created = ci.create_identity_pool(
        IdentityPoolName=valid_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = created["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    assert created["IdentityPoolName"] == valid_name, (
        f"positive control: expected pool name {valid_name!r}, got {created['IdentityPoolName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
