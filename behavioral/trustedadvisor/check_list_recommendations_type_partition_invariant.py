"""list-recommendations-type-partition-invariant."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-type-partition-invariant"
GROUP = "list-filtering"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"


def _list_recommendations(client, **kwargs):
    """Every ListRecommendations summary for these filters, following nextToken."""
    items = []
    token = None
    for _ in range(50):
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = client.list_recommendations(**params)
        items.extend(resp.get("recommendationSummaries", []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Standard and priority ListRecommendations results exactly partition the unfiltered set; without a
    support-level entitlement, ListRecommendations fails with AccessDeniedException (HTTP 403) "Access
    denied due to support level" instead of returning an empty catalog."""
    ta = ctx.client("trustedadvisor")
    try:
        all_recs = _list_recommendations(ta, maxResults=100)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert code == "AccessDeniedException", (
            f"ListRecommendations: expected AccessDeniedException, got {code!r} ({message!r})"
        )
        assert message == SUPPORT_LEVEL_DENIAL, (
            f"ListRecommendations: expected the denial message {SUPPORT_LEVEL_DENIAL!r}, got {message!r}"
        )
        assert status == 403, f"ListRecommendations: expected HTTP 403 for the gate, got {status}"
        return
    standard = _list_recommendations(ta, type="standard", maxResults=100)
    priority = _list_recommendations(ta, type="priority", maxResults=100)

    for r in standard:
        assert r["type"] == "standard"
    for r in priority:
        assert r["type"] == "priority"

    assert len(standard) + len(priority) == len(all_recs), (
        f"standard({len(standard)}) + priority({len(priority)}) != unfiltered({len(all_recs)})"
    )
    all_ids = {(r["id"], r["arn"]) for r in all_recs}
    split_ids = {(r["id"], r["arn"]) for r in standard} | {(r["id"], r["arn"]) for r in priority}
    assert all_ids == split_ids, "type-partitioned id set differs from unfiltered id set"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
