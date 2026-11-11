"""describe-identity-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-identity-not-found"
GROUP = 'error-semantics'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeIdentity on a well-formed but never-issued IdentityId returns ResourceNotFoundException."""
    ci = ctx.client("cognito-identity")

    # Positive control: prove DescribeIdentity works at all in this account before its refusal on a
    # bogus id means anything — otherwise "rejects a never-issued id" is indistinguishable from
    # "rejects every DescribeIdentity call".
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    real_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    described = ci.describe_identity(IdentityId=real_id)
    assert described["IdentityId"] == real_id, (
        f"expected DescribeIdentity to succeed for a real identity, got {described!r}"
    )

    bogus_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    err = _error(lambda: ci.describe_identity(IdentityId=bogus_id))
    expected = ("ResourceNotFoundException", f"Identity '{bogus_id}' not found.")
    assert err == expected, f"expected {expected}, got {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
