"""op-contract-describe-user-pool."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "op-contract-describe-user-pool"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeUserPool returns the created pool's identity/config; a bogus pool id 404s."""
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-behav-pool-")
    before = datetime.now(timezone.utc)
    created = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = created["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    desc = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    after = datetime.now(timezone.utc)
    assert desc["Id"] == pool_id
    assert desc["Name"] == name
    creation_date = desc.get("CreationDate")
    assert creation_date is not None, "expected CreationDate to be populated"
    window_start, window_end = before - timedelta(minutes=1), after + timedelta(minutes=1)
    assert window_start <= creation_date <= window_end, (
        f"expected CreationDate in [{window_start}, {window_end}], got {creation_date}"
    )
    assert "Policies" in desc and "PasswordPolicy" in desc["Policies"]
    assert "Arn" in desc and pool_id in desc["Arn"], desc.get("Arn")

    # A syntactically valid pool id (region prefix + suffix) that was never created: the
    # region prefix form matters, since a target that only pattern-matches the id would
    # otherwise reject this for the wrong reason.
    bogus_id = f"{ctx.region}_ZZZZZZZZZ"
    err = _client_error(lambda: idp.describe_user_pool(UserPoolId=bogus_id))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = f"User pool {bogus_id} does not exist."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
