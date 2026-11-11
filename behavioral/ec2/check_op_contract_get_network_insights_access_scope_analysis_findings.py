"""op-contract-get-network-insights-access-scope-analysis-findings."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-network-insights-access-scope-analysis-findings"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNetworkInsightsAccessScopeAnalysisFindings reports the terminal status and
    findings of a real access-scope analysis, and rejects an unknown analysis id.
    """
    ec2 = ctx.client("ec2")

    scope = ec2.create_network_insights_access_scope(
        TagSpecifications=[
            {
                "ResourceType": "network-insights-access-scope",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nias-")}],
            }
        ]
    )["NetworkInsightsAccessScope"]
    scope_id = scope["NetworkInsightsAccessScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=scope_id))

    analysis = ec2.start_network_insights_access_scope_analysis(
        NetworkInsightsAccessScopeId=scope_id
    )["NetworkInsightsAccessScopeAnalysis"]
    analysis_id = analysis["NetworkInsightsAccessScopeAnalysisId"]
    ctx.on_cleanup(
        lambda: ec2.delete_network_insights_access_scope_analysis(
            NetworkInsightsAccessScopeAnalysisId=analysis_id
        )
    )

    terminal_status = _poll_until(
        lambda: ec2.describe_network_insights_access_scope_analyses(
            NetworkInsightsAccessScopeAnalysisIds=[analysis_id]
        )["NetworkInsightsAccessScopeAnalyses"][0]["Status"],
        lambda status: status in ("succeeded", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert terminal_status == "succeeded", f"analysis did not succeed: {terminal_status!r}"

    # success-path contract: findings response echoes the analysis id and status, and
    # is a well-formed (possibly empty) list.
    findings_resp = ec2.get_network_insights_access_scope_analysis_findings(
        NetworkInsightsAccessScopeAnalysisId=analysis_id
    )
    assert findings_resp["NetworkInsightsAccessScopeAnalysisId"] == analysis_id
    assert findings_resp["AnalysisStatus"] == "succeeded"
    assert isinstance(findings_resp["AnalysisFindings"], list)

    # error boundary: a well-formed but nonexistent analysis id is rejected. AWS rejects
    # this placeholder-style id generically (InvalidParameterValue)
    # rather than with a resource-specific *.NotFound/*.Malformed code, since it doesn't match the
    # real analysis-id shape closely enough to run the specific-id validator.
    code, message, _ = _client_error(
        lambda: ec2.get_network_insights_access_scope_analysis_findings(
            NetworkInsightsAccessScopeAnalysisId="nisa-00000000000000000"
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "NetworkInsightsAccessScopeAnalysisId (nisa-00000000000000000) is not valid", f"unexpected InvalidParameterValue message: {message!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never reached within {timeout_s}s, last value {result!r}")


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
