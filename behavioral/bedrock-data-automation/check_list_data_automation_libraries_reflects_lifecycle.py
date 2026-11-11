"""list-data-automation-libraries-reflects-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-data-automation-libraries-reflects-lifecycle"
GROUP = "listing"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataAutomationLibraries includes a newly created Library and stops including it once
    deleted."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-lib-list")
    arn = bda.create_data_automation_library(
        libraryName=name, tags=[{"key": "env", "value": "sim2real"}]
    )["libraryArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(bda, arn))

    found = _poll_until(
        lambda: arn in _list_all_library_arns(bda),
        lambda present: present,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert found, f"expected {arn} in ListDataAutomationLibraries within 30s, never appeared"

    bda.delete_data_automation_library(libraryArn=arn)

    gone = _poll_until(
        lambda: arn in _list_all_library_arns(bda),
        lambda present: not present,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert not gone, f"expected {arn} removed from ListDataAutomationLibraries within 30s, still present"


def _delete_ignore_missing(bda, library_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bda.delete_data_automation_library(libraryArn=library_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_library_arns(bda) -> set:
    arns: set = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = bda.list_data_automation_libraries(**kwargs)
        arns.update(lib["libraryArn"] for lib in resp.get("libraries", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
