"""contributor-insights-disable-while-enabling-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "contributor-insights-disable-while-enabling-rejected"
GROUP = "state-machine"
SERVICES = ["dynamodb"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: ENABLE requests tried before the check gives up on observing the ENABLING window.
_ATTEMPTS = 5
#: Bound on each wait for contributor insights to settle; the runner's remaining time bounds it further.
_SETTLE_TIMEOUT_S = 600.0
_EXPECTED = (
    "Table or Index is not in a valid state to update Key Access Insights: ContributorInsights "
    "Status must be ENABLED or FAILED to perform DISABLE operation."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DISABLE sent while contributor insights are still ENABLING is refused with ValidationException
    and its exact message, and the refused request leaves the insights to settle ENABLED."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddb-cins-")
    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
    )
    ctx.on_cleanup(lambda: _drop(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 90})

    tried = []
    refused = False
    for _ in range(_ATTEMPTS):
        enabled = ddb.update_contributor_insights(TableName=table, ContributorInsightsAction="ENABLE")
        before = _status(ddb, table)
        if before != "ENABLING":
            tried.append(f"ENABLE answered {enabled.get('ContributorInsightsStatus')!r}, then read {before!r}")
            _settle(ctx, ddb, table, "ENABLED")
            _disable_and_settle(ctx, ddb, table)
            continue
        code, message = _outcome(
            lambda: ddb.update_contributor_insights(TableName=table, ContributorInsightsAction="DISABLE"))
        if (code, message) == ("ValidationException", _EXPECTED):
            refused = True
            break
        assert code == _ACCEPTED, (
            f"DISABLE while ENABLING answered {code!r} {message!r}; "
            f"expected ValidationException {_EXPECTED!r}"
        )
        after = _settle(ctx, ddb, table, "DISABLED")
        assert after == "DISABLED", (
            f"the accepted DISABLE left the insights {after!r}, expected 'DISABLED'"
        )
        tried.append(f"DISABLE accepted after the status read {before!r}; settled {after!r}")
    assert refused, f"DISABLE was never refused while ENABLING in {_ATTEMPTS} attempts: {tried!r}"

    final = _settle(ctx, ddb, table, "ENABLED")
    assert final == "ENABLED", f"after the refused DISABLE the insights settled {final!r}, expected 'ENABLED'"


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _status(ddb, table: str) -> str:
    return ddb.describe_contributor_insights(TableName=table)["ContributorInsightsStatus"]


def _settle(ctx, ddb, table: str, target: str) -> str:
    """Poll until the insights reach ``target`` or FAILED; returns the status reached."""
    left = ctx.time_left()
    timeout = _SETTLE_TIMEOUT_S if left is None else max(1.0, min(_SETTLE_TIMEOUT_S, left - min(60.0, left / 4)))
    deadline = time.monotonic() + timeout
    status = _status(ddb, table)
    while status not in (target, "FAILED"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"contributor insights still {status!r} after {timeout:.0f}s, waiting for {target!r}")
        time.sleep(2)
        status = _status(ddb, table)
    return status


def _disable_and_settle(ctx, ddb, table: str) -> None:
    ddb.update_contributor_insights(TableName=table, ContributorInsightsAction="DISABLE")
    _settle(ctx, ddb, table, "DISABLED")


def _drop(ddb, table: str) -> None:
    """Delete the table; already gone counts as deleted."""
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
