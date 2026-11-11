"""response-contract-field-shapes."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "response-contract-field-shapes"
GROUP = "contract"
SERVICES = ["bcm-recommended-actions"]

_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_TIMESTAMP_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every ListRecommendedActions item has a non-empty string id, feature and type, a 12-digit
    accountId, a known severity, string-to-string context, string nextSteps and a date-prefixed
    lastUpdatedTimeStamp."""
    client = ctx.client("bcm-recommended-actions")
    resp = client.list_recommended_actions(maxResults=1000)

    assert "recommendedActions" in resp, f"missing recommendedActions key: {resp!r}"
    actions = resp["recommendedActions"]
    assert isinstance(actions, list), f"expected list, got {type(actions).__name__}"
    if not actions:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so the per-item shape assertions below cannot be exercised -- "
            "needs a sandbox account with at least one naturally-occurring action"
        )

    for action in actions:
        assert isinstance(action["id"], str) and len(action["id"]) > 0, (
            f"expected non-empty string id, got {action['id']!r}"
        )
        assert _ACCOUNT_ID_RE.match(action["accountId"]), (
            f"expected 12-digit accountId, got {action['accountId']!r}"
        )
        assert action["severity"] in _VALID_SEVERITIES, (
            f"expected severity in {_VALID_SEVERITIES}, got {action['severity']!r}"
        )
        assert isinstance(action["feature"], str) and len(action["feature"]) > 0, (
            f"expected non-empty string feature, got {action['feature']!r}"
        )
        assert isinstance(action["type"], str) and len(action["type"]) > 0, (
            f"expected non-empty string type, got {action['type']!r}"
        )

        context = action.get("context", {})
        assert isinstance(context, dict), f"expected dict context, got {type(context).__name__}"
        for key, value in context.items():
            assert isinstance(key, str), f"expected string context key, got {key!r}"
            assert isinstance(value, str), f"expected string context value, got {value!r}"

        next_steps = action.get("nextSteps", [])
        assert isinstance(next_steps, list), (
            f"expected list nextSteps, got {type(next_steps).__name__}"
        )
        for step in next_steps:
            assert isinstance(step, str), f"expected string nextSteps entry, got {step!r}"

        ts = action.get("lastUpdatedTimeStamp")
        if ts is not None:
            assert isinstance(ts, str), f"expected string lastUpdatedTimeStamp, got {type(ts).__name__}"
            assert _TIMESTAMP_PREFIX_RE.match(ts), (
                f"expected lastUpdatedTimeStamp to start YYYY-MM-DD, got {ts!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
