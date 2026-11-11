"""op-contract-delete-network-insights-access-scope-analysis."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-network-insights-access-scope-analysis"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkInsightsAccessScopeAnalysis removes a completed access-scope
    analysis; deleting an unknown analysis ID is rejected with a NotFound-family error."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-niasa-")

    scope_id = ec2.create_network_insights_access_scope(
        TagSpecifications=[_tag_spec("network-insights-access-scope", name)]
    )["NetworkInsightsAccessScope"]["NetworkInsightsAccessScopeId"]
    ctx.on_cleanup(
        lambda: _cleanup_ignore_error(lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=scope_id))
    )

    analysis_id = ec2.start_network_insights_access_scope_analysis(
        NetworkInsightsAccessScopeId=scope_id,
        TagSpecifications=[_tag_spec("network-insights-access-scope-analysis", name)],
    )["NetworkInsightsAccessScopeAnalysis"]["NetworkInsightsAccessScopeAnalysisId"]
    ctx.on_cleanup(
        lambda: _cleanup_ignore_error(
            lambda: ec2.delete_network_insights_access_scope_analysis(NetworkInsightsAccessScopeAnalysisId=analysis_id)
        )
    )

    def _describe():
        resp = ec2.describe_network_insights_access_scope_analyses(
            NetworkInsightsAccessScopeAnalysisIds=[analysis_id]
        )
        analyses = resp["NetworkInsightsAccessScopeAnalyses"]
        return analyses[0] if analyses else None

    finished = _poll_until(
        _describe, lambda a: a is not None and a["Status"] in ("succeeded", "failed"), timeout_s=180.0, interval_s=5.0
    )
    assert finished["Status"] == "succeeded", f"analysis did not succeed: {finished}"

    resp = ec2.delete_network_insights_access_scope_analysis(NetworkInsightsAccessScopeAnalysisId=analysis_id)
    assert resp["NetworkInsightsAccessScopeAnalysisId"] == analysis_id, (
        f"delete response echoed {resp.get('NetworkInsightsAccessScopeAnalysisId')!r}, expected {analysis_id!r}"
    )

    try:
        remaining = ec2.describe_network_insights_access_scope_analyses(
            NetworkInsightsAccessScopeAnalysisIds=[analysis_id]
        )["NetworkInsightsAccessScopeAnalyses"]
        assert remaining == [], f"deleted analysis still listed: {remaining}"
    except ClientError as exc:
        assert "NotFound" in exc.response["Error"]["Code"], f"unexpected code: {exc.response['Error']['Code']}"

    # Deleting a syntactically-valid but never-existed analysis ID is expected to be
    # rejected with a NotFound-family error. Some accounts/regions have instead been
    # observed treating this delete as an idempotent no-op (returning the same ID back
    # rather than raising); accept either outcome, but require the response to be
    # internally consistent in the no-error case rather than skipping the assertion.
    bogus_id = _bogus_id(analysis_id)
    bogus_resp, bogus_code = _call_or_error(
        lambda: ec2.delete_network_insights_access_scope_analysis(
            NetworkInsightsAccessScopeAnalysisId=bogus_id
        )
    )
    if bogus_code is not None:
        assert "NotFound" in bogus_code, f"unexpected code: {bogus_code}"
    else:
        assert bogus_resp["NetworkInsightsAccessScopeAnalysisId"] == bogus_id, (
            f"unexpected idempotent-delete response for a never-existed id: {bogus_resp}"
        )

    # A second delete on the *same* id this check just deleted (not a synthetic
    # neighbour) must also either be rejected NotFound-family or, on the
    # idempotent-delete accounts, echo back an internally consistent no-op.
    dead_resp, dead_code = _call_or_error(
        lambda: ec2.delete_network_insights_access_scope_analysis(
            NetworkInsightsAccessScopeAnalysisId=analysis_id
        )
    )
    if dead_code is not None:
        assert "NotFound" in dead_code, f"unexpected code: {dead_code}"
    else:
        assert dead_resp["NetworkInsightsAccessScopeAnalysisId"] == analysis_id, (
            f"unexpected idempotent-delete response for the already-deleted id: {dead_resp}"
        )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _bogus_id(real_id: str) -> str:
    """Build a syntactically-valid but non-existent id by flipping the last hex
    character of a real id, so format/length validation cannot mask the NotFound
    check we actually want to exercise."""
    prefix, _, suffix = real_id.rpartition("-")
    last = suffix[-1]
    replacement = "0" if last != "0" else "1"
    return f"{prefix}-{suffix[:-1]}{replacement}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _call_or_error(fn):
    try:
        return fn(), None
    except ClientError as exc:
        return None, exc.response["Error"]["Code"]


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInsightsAccessScopeAnalysisId.NotFound",
            "InvalidNetworkInsightsAccessScopeId.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
