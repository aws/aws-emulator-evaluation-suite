"""get-investigation-nonexistent-id-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-investigation-nonexistent-id-not-found"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """GetInvestigation for a well-formed but never-created InvestigationId is rejected; a valid list call still works."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    # Well-formed per the InvestigationId shape (fixed length 21, digits only) but never issued.
    fake_investigation_id = "2" * 21

    code, message = _error(lambda: d.get_investigation(GraphArn=arn, InvestigationId=fake_investigation_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The specified investigation does not exist", f"unexpected message: {message!r}"

    # positive control: the graph and its investigation listing are otherwise usable, and
    # the fabricated id -- never created -- must not appear in it.
    investigations = d.list_investigations(GraphArn=arn).get("InvestigationDetails", [])
    seen_ids = [inv.get("InvestigationId") for inv in investigations]
    assert fake_investigation_id not in seen_ids, (
        f"fabricated id {fake_investigation_id!r} unexpectedly present in "
        f"list_investigations: {seen_ids!r}"
    )


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
