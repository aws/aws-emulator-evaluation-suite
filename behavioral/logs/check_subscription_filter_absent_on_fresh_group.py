"""subscription-filter-absent-on-fresh-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscription-filter-absent-on-fresh-group"
GROUP = 'subscription-filter'
SERVICES = ['logs']

def _error_code(fn):
    """Call fn(); return the ClientError's code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_log_group(ctx, logs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    return name


def _delete_log_group(logs, name) -> None:
    """Drop deletion protection (if any) before deleting, mirroring the suite's teardown."""
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=name, deletionProtectionEnabled=False
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs.delete_log_group(logGroupName=name)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh log group has no subscription filters, and deleting a missing one is a not-found error."""
    logs = ctx.client("logs")
    group = _create_log_group(ctx, logs)

    filters = logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    assert filters == [], f"fresh log group reported subscription filters: {filters}"

    code, message = _error_code(
        lambda: logs.delete_subscription_filter(
            logGroupName=group, filterName=ctx.unique_name("sim2real-behav-sf-missing-")
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == "The specified subscription filter does not exist.", (
        f"unexpected missing-subscription-filter message: {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
