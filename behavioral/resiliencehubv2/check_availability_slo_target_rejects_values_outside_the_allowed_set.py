"""availability-slo-target-rejects-values-outside-the-allowed-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "availability-slo-target-rejects-values-outside-the-allowed-set"
GROUP = "policy-validation"
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


def _create_policy(ctx, rh, **kwargs) -> dict:
    """A resilience policy deleted at teardown."""
    policy = rh.create_policy(name=ctx.unique_name("sim2real-behav-rhv2-pol-"), **kwargs)["policy"]
    arn = policy["policyArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_policy(policyArn=arn), "ResourceNotFoundException"))
    return policy


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An availability SLO other than 99.9, 99.95 or 99.99 is refused on create and on update, and a
    refused update leaves the stored target unchanged.
    """
    rh = ctx.client("resiliencehubv2")

    def expected(message: str) -> str:
        """The refusal, listing the three allowed targets in the order the message names them."""
        # AWS lists the allowed targets in no fixed order; the set is graded, then the whole text.
        listed = message.rpartition("[")[2].partition("]")[0].split(", ")
        assert sorted(listed) == ["99.9", "99.95", "99.99"], f"allowed targets named: {message!r}"
        return f"Invalid input for field availabilitySlo.target. Allowed values are [{', '.join(listed)}]."
    refused_name = ctx.unique_name("sim2real-behav-rhv2-pol-")
    code, message = _error(lambda: rh.create_policy(name=refused_name, availabilitySlo={"target": 99.0}))
    assert code == "ValidationException", f"CreatePolicy 99.0: {code}: {message!r}"
    assert message == expected(message), f"CreatePolicy 99.0: {message!r}"
    names = [p["name"] for page in rh.get_paginator("list_policies").paginate()
             for p in page["policySummaries"]]
    assert refused_name not in names, "a refused CreatePolicy must not create the policy"

    policy = _create_policy(ctx, rh, availabilitySlo={"target": 99.9})
    code, message = _error(lambda: rh.update_policy(policyArn=policy["policyArn"],
                                                    availabilitySlo={"target": 99.5}))
    assert code == "ValidationException", f"UpdatePolicy 99.5: {code}: {message!r}"
    assert message == expected(message), f"UpdatePolicy 99.5: {message!r}"
    stored = rh.get_policy(policyArn=policy["policyArn"])["policy"]["availabilitySlo"]
    assert stored == {"target": 99.9}, f"a refused update must leave 99.9, got {stored!r}"

    rh.update_policy(policyArn=policy["policyArn"], availabilitySlo={"target": 99.99})
    stored = rh.get_policy(policyArn=policy["policyArn"])["policy"]["availabilitySlo"]
    assert stored == {"target": 99.99}, f"an allowed update must store 99.99, got {stored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
