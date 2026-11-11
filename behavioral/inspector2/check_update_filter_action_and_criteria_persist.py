"""update-filter-action-and-criteria-persist."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "update-filter-action-and-criteria-persist"
GROUP = "state"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFilter from NONE/LOW to SUPPRESS and an EQUALS HIGH severity persists in ListFilters;
    after delete the filter is unlisted and UpdateFilter fails with ResourceNotFoundException and
    AWS's message for it (only the request id varies)."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-filter-upd-")

    created = inspector2.create_filter(
        action="NONE",
        name=name,
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "LOW"}]},
        tags={"Owner": "sim2real", "Stage": "test"},
    )
    arn = created["arn"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            inspector2.delete_filter(arn=arn)

    ctx.on_cleanup(_cleanup)

    before = _find_filter(inspector2, arn)
    assert before["action"] == "NONE", f"expected initial action NONE, got {before['action']}"
    assert before["criteria"]["severity"][0]["value"] == "LOW", (
        f"expected initial severity LOW, got {before['criteria']['severity'][0]['value']}"
    )

    inspector2.update_filter(
        filterArn=arn,
        action="SUPPRESS",
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "HIGH"}]},
    )

    after = _find_filter(inspector2, arn)
    assert after is not None, "updated filter no longer appears in ListFilters"
    assert after["action"] == "SUPPRESS", "action change did not persist"
    assert after["criteria"]["severity"][0]["value"] == "HIGH", "criteria change did not persist"
    assert after["criteria"]["severity"][0]["comparison"] == "EQUALS", (
        f"expected comparison EQUALS, got {after['criteria']['severity'][0]['comparison']}"
    )

    inspector2.delete_filter(arn=arn)
    deleted["done"] = True

    gone = _find_filter(inspector2, arn)
    assert gone is None, f"deleted filter still appears in ListFilters: {gone}"

    try:
        inspector2.update_filter(
            filterArn=arn,
            action="NONE",
            filterCriteria={"severity": [{"comparison": "EQUALS", "value": "LOW"}]},
        )
        raise AssertionError("UpdateFilter on a deleted filterArn unexpectedly succeeded")
    except inspector2.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message", "")
    # The not-found message carries a server-side request id and the backend's own SDK attempt
    # count; everything else is pinned.
    head = f"{arn} does not exist (Service: MandoFindings, Status Code: 404, Request ID: "
    found = re.search(r"Request ID: ([0-9a-f-]{36})\) \(SDK Attempt Count: (\d+)\)$", message or "")
    request_id, attempts = found.groups() if found else ("?", "?")
    expected = f"{head}{request_id}) (SDK Attempt Count: {attempts})"
    assert message == expected, f"expected the message {expected!r}, got {message!r}"


def _find_filter(inspector2, arn: str):
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_filters(**kwargs)
        for f in resp.get("filters", []):
            if f["arn"] == arn:
                return f
        next_token = resp.get("nextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
