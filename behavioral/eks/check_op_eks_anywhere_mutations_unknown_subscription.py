"""op-eks-anywhere-mutations-unknown-subscription."""
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

CHECK = "op-eks-anywhere-mutations-unknown-subscription"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] Update/Delete of an EKS Anywhere subscription that does not exist MUST fail with ResourceNotFoundException rather than silently succeeding."""
    c = ctx.client("eks")
    ghost_id = str(uuid.uuid4())

    # Positive control: the subscriptions API surface itself must be reachable and healthy for this
    # account/credentials. Without this, a target that blanket-denies or blanket-404s every
    # EksAnywhereSubscription call (valid id or not) would satisfy the assertions below for the
    # wrong reason. ListEksAnywhereSubscriptions is free and idempotent, unlike
    # CreateEksAnywhereSubscription, which locks in a non-cancellable 12-month license -- too heavy
    # to pay just to prove connectivity.
    resp = c.list_eks_anywhere_subscriptions()
    assert isinstance(resp.get("subscriptions"), list), f"ListEksAnywhereSubscriptions -> {resp}"

    code, msg = _expect_error(
        lambda: c.update_eks_anywhere_subscription(id=ghost_id, autoRenew=True)
    )
    assert code == "ResourceNotFoundException", (
        f"UpdateEksAnywhereSubscription on unknown id: expected ResourceNotFoundException, got {code}"
    )
    assert msg == "subscription not found.", f"UpdateEksAnywhereSubscription on unknown id -> {msg!r}"

    code, msg = _expect_error(
        lambda: c.delete_eks_anywhere_subscription(id=ghost_id)
    )
    assert code == "ResourceNotFoundException", (
        f"DeleteEksAnywhereSubscription on unknown id: expected ResourceNotFoundException, got {code}"
    )
    assert msg == "subscription not found.", f"DeleteEksAnywhereSubscription on unknown id -> {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
