"""representation-list-workloads-nexttoken-opaque-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "representation-list-workloads-nexttoken-opaque-round-trip"
GROUP = "representation"
SERVICES = ["launch-wizard"]


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkloads with maxResults=1 returns one workload and a nextToken that yields a different workload
    on the next page; a token with one character changed is rejected with ValidationException "NextToken is
    not valid."."""
    lw = ctx.client("launch-wizard")
    page1 = lw.list_workloads(maxResults=1)
    workloads1 = page1["workloads"]
    assert len(workloads1) == 1, f"expected exactly 1 workload with maxResults=1, got {len(workloads1)}"
    next_token = page1.get("nextToken")
    assert next_token, "expected a nextToken since the Launch Wizard catalog has multiple workloads"

    page2 = lw.list_workloads(maxResults=1, nextToken=next_token)
    workloads2 = page2["workloads"]
    assert len(workloads2) == 1, f"expected exactly 1 workload on page 2, got {len(workloads2)}"
    assert workloads2[0]["workloadName"] != workloads1[0]["workloadName"], (
        "second page repeated the first page's workload instead of advancing"
    )

    # tamper a single character of the otherwise-valid opaque token
    last = next_token[-1]
    flipped = "A" if last != "A" else "B"
    tampered_token = next_token[:-1] + flipped
    code, message = _client_error(lambda: lw.list_workloads(maxResults=1, nextToken=tampered_token))
    assert code == "ValidationException", (
        f"expected ValidationException for a tampered nextToken, got {code!r}"
    )
    assert message == "NextToken is not valid.", f"got message={message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
