"""list-analyzers-reflects-type-filter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-analyzers-reflects-type-filter"
GROUP = "state-machine"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """ListAnalyzers(type=...) filters by analyzer type: an ACCOUNT analyzer shows up
    under the ACCOUNT filter but not under the ACCOUNT_UNUSED_ACCESS filter, and vice
    versa for an unused-access analyzer."""
    aa = ctx.client("accessanalyzer")
    account_name = ctx.unique_name("sim2real-aa-filter-acct-")
    unused_name = ctx.unique_name("sim2real-aa-filter-unused-")

    account_arn = aa.create_analyzer(analyzerName=account_name, type="ACCOUNT")["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=account_name))
    unused_arn = aa.create_analyzer(analyzerName=unused_name, type="ACCOUNT_UNUSED_ACCESS")["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=unused_name))

    account_status = _poll_analyzer_status(ctx, account_name)
    unused_status = _poll_analyzer_status(ctx, unused_name)
    assert account_status == "ACTIVE", f"expected ACCOUNT analyzer ACTIVE, got {account_status}"
    assert unused_status == "ACTIVE", f"expected ACCOUNT_UNUSED_ACCESS analyzer ACTIVE, got {unused_status}"

    account_type_arns = {a["arn"] for a in aa.list_analyzers(type="ACCOUNT")["analyzers"]}
    unused_type_arns = {a["arn"] for a in aa.list_analyzers(type="ACCOUNT_UNUSED_ACCESS")["analyzers"]}

    assert account_arn in account_type_arns, f"{account_arn} missing from type=ACCOUNT list {account_type_arns}"
    assert account_arn not in unused_type_arns, f"{account_arn} unexpectedly in type=ACCOUNT_UNUSED_ACCESS list {unused_type_arns}"
    assert unused_arn in unused_type_arns, f"{unused_arn} missing from type=ACCOUNT_UNUSED_ACCESS list {unused_type_arns}"
    assert unused_arn not in account_type_arns, f"{unused_arn} unexpectedly in type=ACCOUNT list {account_type_arns}"


def _poll_analyzer_status(ctx, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    raise TimeoutError(f"analyzer {name} still CREATING after {timeout_s}s (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
