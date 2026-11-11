"""get-csv-header-invalid-pool-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-csv-header-invalid-pool-id-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader against a malformed user pool id (fails the UserPoolId shape
    pattern) is rejected with InvalidParameterException, never a CSV header; the
    same call against a real user pool succeeds and returns a populated header.
    """
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    # Negative: malformed pool id (no "<region>_<id>" shape at all).
    code = _error(lambda: cognito.get_csv_header(UserPoolId="not-a-valid-pool-id"))
    assert code == ("InvalidParameterException", (
        "1 validation error detected: Value 'not-a-valid-pool-id' at 'userPoolId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [\\w-]+_[0-9a-zA-Z]+"
    )), (
        f"expected InvalidParameterException, got {code!r}"
    )

    # Positive control: real pool id succeeds and returns a non-empty header
    # that includes at least the mandatory "cognito:username" column (the
    # AWS-documented CSVHeader always includes this exact column name, not a
    # bare "username").
    resp = cognito.get_csv_header(UserPoolId=pool_id)
    assert resp["UserPoolId"] == pool_id, f"expected UserPoolId={pool_id!r}, got {resp['UserPoolId']!r}"
    assert "cognito:username" in resp["CSVHeader"], (
        f"expected 'cognito:username' in CSVHeader, got {resp['CSVHeader']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message); an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
