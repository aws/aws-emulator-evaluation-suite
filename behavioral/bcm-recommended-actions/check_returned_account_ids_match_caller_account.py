"""returned-account-ids-match-caller-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "returned-account-ids-match-caller-account"
GROUP = "isolation"
SERVICES = ["bcm-recommended-actions"]


def _collect(client, **kwargs):
    items = []
    token = None
    for _ in range(500):
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = client.list_recommended_actions(**params)
        items.extend(resp.get("recommendedActions", []))
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("pagination did not terminate within 500 pages")
    return items


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRecommendedActions is scoped to the calling account: every recommended
    action returned to a caller must carry that same caller's 12-digit accountId,
    never a different account's id -- there is no cross-tenant leakage."""
    sts = ctx.client("sts")
    caller_account_id = sts.get_caller_identity()["Account"]

    bcm = ctx.client("bcm-recommended-actions")
    actions = _collect(bcm)
    if not actions:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so cross-tenant leakage cannot be exercised -- needs a sandbox "
            "account with at least one action"
        )

    for action in actions:
        assert action["accountId"] == caller_account_id, (
            action["accountId"],
            caller_account_id,
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
