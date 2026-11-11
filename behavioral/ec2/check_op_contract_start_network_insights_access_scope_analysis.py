"""op-contract-start-network-insights-access-scope-analysis."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-start-network-insights-access-scope-analysis"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartNetworkInsightsAccessScopeAnalysis drives an access-scope analysis to a terminal
    status; a bogus access scope id is rejected."""
    ec2 = ctx.client("ec2")

    scope = ec2.create_network_insights_access_scope(
        ClientToken=ctx.unique_name("sim2real-behav-scope-tok-"),
        TagSpecifications=[
            {
                "ResourceType": "network-insights-access-scope",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-scope-")}],
            }
        ],
    )["NetworkInsightsAccessScope"]
    scope_id = scope["NetworkInsightsAccessScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=scope_id))

    # success path: start the analysis and drive it to a terminal status
    resp = ec2.start_network_insights_access_scope_analysis(
        NetworkInsightsAccessScopeId=scope_id,
        ClientToken=ctx.unique_name("sim2real-behav-scope-run-"),
        TagSpecifications=[
            {
                "ResourceType": "network-insights-access-scope-analysis",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-scope-run-")}],
            }
        ],
    )
    analysis_id = resp["NetworkInsightsAccessScopeAnalysis"]["NetworkInsightsAccessScopeAnalysisId"]
    ctx.on_cleanup(
        lambda: ec2.delete_network_insights_access_scope_analysis(
            NetworkInsightsAccessScopeAnalysisId=analysis_id
        )
    )

    def probe():
        resp = ec2.describe_network_insights_access_scope_analyses(
            NetworkInsightsAccessScopeAnalysisIds=[analysis_id]
        )
        analyses = resp.get("NetworkInsightsAccessScopeAnalyses", [])
        return analyses[0]["Status"] if analyses else None

    # _poll_until's own predicate already stops only at a terminal status; a bare
    # `status in ("succeeded", "failed")` re-check afterwards cannot fail. With no
    # PathsToMatch/ExcludePaths constraints on the scope, the real terminal outcome
    # is deterministically "succeeded", so assert that directly.
    status = _poll_until(probe, lambda s: s in ("succeeded", "failed"), timeout_s=180.0)
    assert status == "succeeded", f"expected the unconstrained scope analysis to succeed, got {status!r}"

    # error boundary: nonexistent access scope id
    code, message = _error(
        lambda: ec2.start_network_insights_access_scope_analysis(
            NetworkInsightsAccessScopeId="nis-00000000000000000",
            ClientToken=ctx.unique_name("sim2real-behav-scope-bad-"),
        )
    )
    assert code == "InvalidParameterValue", code
    assert message == "NetworkInsightsAccessScopeId (nis-00000000000000000) is not valid", (
        f"unexpected InvalidParameterValue message {message!r}")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
