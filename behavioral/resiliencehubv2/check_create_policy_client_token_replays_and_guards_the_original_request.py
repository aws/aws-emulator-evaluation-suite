"""create-policy-client-token-replays-and-guards-the-original-request."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-client-token-replays-and-guards-the-original-request"
GROUP = "idempotency"
SERVICES = ["resiliencehubv2"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CreatePolicy repeated with the same clientToken returns the same policy without a second
    one, and the token reused with different parameters is refused with ConflictException.
    """
    rh = ctx.client("resiliencehubv2")
    name = ctx.unique_name("sim2real-behav-rhv2-pol-")
    token = f"sim2real-{uuid.uuid4().hex}"
    first = rh.create_policy(name=name, clientToken=token, availabilitySlo={"target": 99.9})["policy"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_policy(policyArn=first["policyArn"]), "ResourceNotFoundException"))

    again = rh.create_policy(name=name, clientToken=token, availabilitySlo={"target": 99.9})["policy"]
    assert again["policyArn"] == first["policyArn"], "the replayed request must return the same policy ARN"
    assert again["createdAt"] == first["createdAt"], "the replayed request must return the original policy"

    code, message = _error(lambda: rh.create_policy(name=name, clientToken=token,
                                                    availabilitySlo={"target": 99.99}))
    assert (code, message) == (
        "ConflictException",
        f"Got two different request with the same token: {token}, please use a different token",
    ), f"token reuse with other parameters: {code}: {message!r}"

    named = [p["policyArn"] for page in rh.get_paginator("list_policies").paginate()
             for p in page["policySummaries"] if p["name"] == name]
    assert named == [first["policyArn"]], f"expected exactly one policy named after the token run, got {len(named)}"
    stored = rh.get_policy(policyArn=first["policyArn"])["policy"]["availabilitySlo"]
    assert stored == {"target": 99.9}, f"the refused request must not change the policy, got {stored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
