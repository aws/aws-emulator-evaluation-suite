"""eks-anywhere-subscription-read-semantics."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


CHECK = "eks-anywhere-subscription-read-semantics"
GROUP = 'eks-anywhere'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEksAnywhereSubscription on an unknown id is ResourceNotFoundException, and
    ListEksAnywhereSubscriptions, read before and after as the control, never lists that id."""
    c = ctx.client("eks")
    unknown_id = str(uuid.uuid4())

    listed = {s["id"] for s in _list_all(c)}
    assert unknown_id not in listed, f"{unknown_id} listed before any call: {listed}"

    # No Describe of a real subscription is possible: creating one is a paid 12-month commitment.
    code, message = _expect_error(lambda: c.describe_eks_anywhere_subscription(id=unknown_id))
    assert (code, message) == ("ResourceNotFoundException", "subscription not found."), (code, message)

    listed = {s["id"] for s in _list_all(c)}
    assert unknown_id not in listed, f"the unknown id surfaced in the listing: {listed}"


def _list_all(c):
    subscriptions, token = [], None
    while True:
        resp = c.list_eks_anywhere_subscriptions(**({"nextToken": token} if token else {}))
        subscriptions.extend(resp.get("subscriptions", []))
        token = resp.get("nextToken")
        if not token:
            return subscriptions


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
