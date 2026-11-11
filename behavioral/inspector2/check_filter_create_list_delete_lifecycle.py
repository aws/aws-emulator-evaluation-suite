"""filter-create-list-delete-lifecycle."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "filter-create-list-delete-lifecycle"
GROUP = "state"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created filter is listed and, after DeleteFilter, unlisted; UpdateFilter on its ARN then
    fails with ResourceNotFoundException and AWS's message for it (only the request id varies)."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-filter-")

    created = inspector2.create_filter(
        action="NONE",
        name=name,
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "HIGH"}]},
        tags={"sim2real-check": CHECK},
    )
    arn = created["arn"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            inspector2.delete_filter(arn=arn)

    ctx.on_cleanup(_cleanup)

    arns_after_create = _all_filter_arns(inspector2)
    assert arn in arns_after_create, "newly created filter did not appear in ListFilters"

    inspector2.delete_filter(arn=arn)
    deleted["done"] = True

    arns_after_delete = _all_filter_arns(inspector2)
    assert arn not in arns_after_delete, "deleted filter still appears in ListFilters"

    code, message = _error(
        lambda: inspector2.update_filter(
            filterArn=arn,
            action="SUPPRESS",
            filterCriteria={"severity": [{"comparison": "EQUALS", "value": "HIGH"}]},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected UpdateFilter on a deleted filter arn to fail with ResourceNotFoundException, got {code!r}"
    )
    # The not-found message carries a server-side request id and the backend's own SDK attempt
    # count; everything else is pinned.
    head = f"{arn} does not exist (Service: MandoFindings, Status Code: 404, Request ID: "
    found = re.search(r"Request ID: ([0-9a-f-]{36})\) \(SDK Attempt Count: (\d+)\)$", message or "")
    request_id, attempts = found.groups() if found else ("?", "?")
    expected = f"{head}{request_id}) (SDK Attempt Count: {attempts})"
    assert message == expected, f"expected the message {expected!r}, got {message!r}"


def _error(fn):
    """``(code, message)`` of a refused call; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected the call to fail, but it succeeded")
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")


def _all_filter_arns(inspector2) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_filters(**kwargs)
        for f in resp.get("filters", []):
            arns.add(f["arn"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
