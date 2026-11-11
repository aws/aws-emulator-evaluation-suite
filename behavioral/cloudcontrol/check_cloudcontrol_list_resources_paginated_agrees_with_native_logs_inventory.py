"""cloudcontrol-list-resources-paginated-agrees-with-native-logs-inventory."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-list-resources-paginated-agrees-with-native-logs-inventory"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
GROUPS = 6
RETENTION = 1
PAGE_LIMIT = 500


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, *, timeout_s=120, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} reaching a terminal OperationStatus",
    )


def _delete_log_group_quiet(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """ListResources walked over every page agrees exactly with a paginated CloudWatch Logs inventory
    of the six log groups created through Cloud Control (no truncation, duplicate or phantom entry),
    and each carries its requested RetentionInDays natively.
    """
    cc = ctx.client("cloudcontrol")
    logs = ctx.client("logs")
    prefix = ctx.unique_name("sim2real-behav-ccpage-")
    names = [f"{prefix}-{i}" for i in range(GROUPS)]

    for name in names:
        resp = cc.create_resource(
            TypeName=LOG_GROUP_TYPE,
            DesiredState=json.dumps({
                "LogGroupName": name, "RetentionInDays": RETENTION,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }),
        )
        ctx.on_cleanup(lambda n=name: _delete_log_group_quiet(logs, n))
        event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
        assert event["OperationStatus"] == "SUCCESS", f"create of {name!r} did not succeed: {event!r}"

    # ListResources is walked on its NextToken rather than through a botocore paginator, because
    # MaxResults is documented "Reserved." on this operation and is not an available page control.
    all_identifiers = []
    next_token = None
    pages = 0
    terminal_page = None
    while True:
        kwargs = {"TypeName": LOG_GROUP_TYPE}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cc.list_resources(**kwargs)
        pages += 1
        all_identifiers.extend(d["Identifier"] for d in page["ResourceDescriptions"])
        next_token = page.get("NextToken")
        if not next_token:
            terminal_page = page
            break
        assert pages <= PAGE_LIMIT, (
            f"ListResources still returned a NextToken after {pages!r} pages: pagination does not "
            "terminate"
        )

    assert "NextToken" not in terminal_page, (
        f"the terminal page still carries a NextToken: {sorted(terminal_page)!r}"
    )
    assert len(all_identifiers) == len(set(all_identifiers)), (
        f"ListResources repeated an identifier across its {pages!r} pages: "
        f"{sorted(all_identifiers)!r}"
    )

    mine_cc = {i for i in all_identifiers if i.startswith(prefix)}
    native = {}
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix):
        for group in page["logGroups"]:
            native[group["logGroupName"]] = group
    assert mine_cc == set(native), (
        f"cloudcontrol reports {sorted(mine_cc)!r} but CloudWatch Logs reports "
        f"{sorted(native)!r}"
    )
    assert len(mine_cc) == GROUPS, (
        f"{len(mine_cc)!r} of this run's {GROUPS!r} log groups are in both inventories: "
        f"{sorted(mine_cc)!r}"
    )
    retentions = {g.get("retentionInDays") for g in native.values()}
    assert retentions == {RETENTION}, (
        f"CloudWatch Logs reports retentions {retentions!r}; every group was created through Cloud "
        f"Control with RetentionInDays={RETENTION!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
