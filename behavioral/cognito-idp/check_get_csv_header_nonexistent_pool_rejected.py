"""get-csv-header-nonexistent-pool-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-csv-header-nonexistent-pool-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader on a pool id never created fails with ResourceNotFoundException and its exact
    message, while a real pool returns a header that includes cognito:username."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    fake_pool_id = f"{ctx.region}_zzNonexistent00"
    code, message = _error(lambda: cognito.get_csv_header(UserPoolId=fake_pool_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"User pool {fake_pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the real pool returns an actual, non-empty CSV header
    header = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert isinstance(header, list) and len(header) > 0, f"expected a non-empty CSV header list, got {header!r}"
    assert "cognito:username" in header, f"expected 'cognito:username' column, got {header!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
