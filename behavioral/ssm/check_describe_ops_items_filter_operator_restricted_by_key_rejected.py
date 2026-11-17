"""describe-ops-items-filter-operator-restricted-by-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-ops-items-filter-operator-restricted-by-key-rejected"
GROUP = "filtering"
SERVICES = ["ssm"]


def _error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeOpsItems accepts Priority only with the Equal operator; GreaterThan on the
    same key is refused OpsCenterInvalidArgumentException, while Equal on the identical
    key and value succeeds."""
    ssm = ctx.client("ssm")
    source = ctx.unique_name("sim2real-ops-operator-")

    ops_item_id = ssm.create_ops_item(
        Title=f"sim2real operator restriction {source}",
        Description="sim2real behavioral test ops item",
        Source=source,
        Priority=3,
    )["OpsItemId"]
    ctx.on_cleanup(lambda: ssm.delete_ops_item(OpsItemId=ops_item_id))

    def _describe(filters):
        return ssm.describe_ops_items(OpsItemFilters=filters)["OpsItemSummaries"]

    def _poll(filters, predicate, attempts=15, delay=2.0):
        """DescribeOpsItems is backed by an eventually-consistent index."""
        ids = [s["OpsItemId"] for s in _describe(filters)]
        for _ in range(attempts):
            if predicate(ids):
                return ids
            time.sleep(delay)
            ids = [s["OpsItemId"] for s in _describe(filters)]
        return ids

    source_filter = {"Key": "Source", "Values": [source], "Operator": "Equal"}

    # Positive control: Priority with Equal, on the same key and value, succeeds.
    equal_ids = _poll(
        [source_filter, {"Key": "Priority", "Values": ["3"], "Operator": "Equal"}],
        lambda ids: ids == [ops_item_id],
    )
    assert equal_ids == [ops_item_id], (
        f"Priority Equal '3' returned {equal_ids}, expected only the created item"
    )

    # GreaterThan is a valid OpsItemFilterOperator value, but Priority does not accept it.
    err = _error(
        lambda: ssm.describe_ops_items(
            OpsItemFilters=[source_filter, {"Key": "Priority", "Values": ["2"], "Operator": "GreaterThan"}]
        )
    )
    assert err["Code"] == "OpsCenterInvalidArgumentException", err
    assert err.get("Message") == "InvalidFilter", f"unexpected message: {err.get('Message')!r}"

    # The identical call, reverted to the accepted operator, still succeeds.
    equal_ids_again = _poll(
        [source_filter, {"Key": "Priority", "Values": ["3"], "Operator": "Equal"}],
        lambda ids: ids == [ops_item_id],
    )
    assert equal_ids_again == [ops_item_id], (
        f"Priority Equal '3' returned {equal_ids_again} after the refused call, expected only the created item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
