"""put-retention-policy-invalid-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-retention-policy-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRetentionPolicy refuses a retentionInDays outside the documented values with
    InvalidParameterException and its exact message, and the group keeps its 7-day retention.
    """
    logs = ctx.client("logs")
    log_group = ctx.unique_name("sim2real-behav-retention-lg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    # Positive control: a valid value is accepted and reflected, so the account
    # and credentials are otherwise healthy for this operation before the
    # rejection below is trusted as a real boundary rather than a blanket deny.
    logs.put_retention_policy(logGroupName=log_group, retentionInDays=7)
    described = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    assert described, "log group missing right after a valid PutRetentionPolicy call"
    assert described[0].get("retentionInDays") == 7, (
        f"positive control failed: expected retentionInDays=7, got {described[0]}"
    )

    code, message = _client_error(
        lambda: logs.put_retention_policy(logGroupName=log_group, retentionInDays=999)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an out-of-range retentionInDays, got {code}"
    )
    assert message == (
        "Invalid retention value. Valid values are: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, "
        "365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]"
    ), f"unexpected message: {message!r}"

    described2 = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    assert described2, "log group disappeared after a rejected PutRetentionPolicy call"
    assert described2[0].get("retentionInDays") == 7, (
        f"PutRetentionPolicy partially applied an invalid retention value: {described2[0]}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
