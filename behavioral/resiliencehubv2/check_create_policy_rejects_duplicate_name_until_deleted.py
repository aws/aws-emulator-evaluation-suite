"""create-policy-rejects-duplicate-name-until-deleted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-rejects-duplicate-name-until-deleted"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second policy with a live policy's name is refused with ConflictException, and the name is
    free again once that policy is deleted.
    """
    rh = ctx.client("resiliencehubv2")
    name = ctx.unique_name("sim2real-behav-rhv2-pol-")
    first = rh.create_policy(name=name, availabilitySlo={"target": 99.9})["policy"]["policyArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_policy(policyArn=first), "ResourceNotFoundException"))

    code, message = _error(lambda: rh.create_policy(name=name, availabilitySlo={"target": 99.99}))
    assert (code, message) == ("ConflictException", f"Policy with name already exists: {name}"), (
        f"duplicate CreatePolicy: {code}: {message!r}"
    )
    kept = rh.get_policy(policyArn=first)["policy"]["availabilitySlo"]
    assert kept == {"target": 99.9}, f"the refused create must not change the live policy, got {kept!r}"

    rh.delete_policy(policyArn=first)
    second = rh.create_policy(name=name, availabilitySlo={"target": 99.99})["policy"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_policy(policyArn=second["policyArn"]), "ResourceNotFoundException"))
    assert second["policyArn"] != first, "the re-created policy must carry a new ARN"
    assert second["availabilitySlo"] == {"target": 99.99}, f"got {second['availabilitySlo']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
