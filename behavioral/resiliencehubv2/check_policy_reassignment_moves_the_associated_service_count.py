"""policy-reassignment-moves-the-associated-service-count."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-reassignment-moves-the-associated-service-count"
GROUP = "policy-association"
SERVICES = ["resiliencehubv2"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "resiliencehub.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


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


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _invoker_role(ctx, iam) -> str:
    """An IAM role resiliencehub may assume, deleted at teardown."""
    name = ctx.unique_name("sim2real-behav-rhv2-role-")
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return name


def _create_service(ctx, rh, role: str, **kwargs) -> dict:
    """CreateService, retried only while IAM has not yet made the new invoker role assumable."""
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-rhv2-svc-"))
    unassumable = (
        f"Cannot assume invoker role '{role}'. Ensure the role exists and its trust policy "
        "allows access."
    )
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            service = rh.create_service(
                regions=[ctx.region], permissionModel={"invokerRoleName": role}, **kwargs
            )["service"]
            break
        except ClientError as exc:
            if exc.response["Error"].get("Message") != unassumable:
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("invoker role becoming assumable: the run budget ended first; not graded") from exc
                raise
        # IAM propagation exposes no condition to poll; the retry above is what waits.
        time.sleep(5)
    arn = service["serviceArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_service(serviceArn=arn), "ResourceNotFoundException"))
    return service


def _create_policy(ctx, rh, **kwargs) -> dict:
    """A resilience policy deleted at teardown."""
    policy = rh.create_policy(name=ctx.unique_name("sim2real-behav-rhv2-pol-"), **kwargs)["policy"]
    arn = policy["policyArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_policy(policyArn=arn), "ResourceNotFoundException"))
    return policy


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Moving a service from one policy to another moves associatedServiceCount and the
    ListServices policyArn filter with it.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    first = _create_policy(ctx, rh, availabilitySlo={"target": 99.9})
    second = _create_policy(ctx, rh, availabilitySlo={"target": 99.95})
    first_arn, second_arn = first["policyArn"], second["policyArn"]
    assert first["associatedServiceCount"] == 0, f"a new policy has no services: {first!r}"
    service = _create_service(ctx, rh, role, policyArn=first_arn)
    arn = service["serviceArn"]

    def counts():
        return tuple(rh.get_policy(policyArn=p)["policy"]["associatedServiceCount"] for p in (first_arn, second_arn))

    def listed(policy_arn):
        return [s["serviceArn"] for s in rh.list_services(policyArn=policy_arn)["serviceSummaries"]]

    assert counts() == (1, 0), f"expected (1, 0) after create, got {counts()!r}"
    assert listed(first_arn) == [arn] and listed(second_arn) == [], "ListServices by policy before the move"

    moved = rh.update_service(serviceArn=arn, policyArn=second_arn)["service"]
    assert moved["policyArn"] == second_arn, "UpdateService must report the new policyArn"
    assert counts() == (0, 1), f"expected (0, 1) after the move, got {counts()!r}"
    assert listed(first_arn) == [] and listed(second_arn) == [arn], "ListServices by policy after the move"
    eff = rh.get_service(serviceArn=arn)["service"]["effectivePolicyValues"]
    assert eff["availabilitySlo"]["value"] == 99.95, f"effective values follow the new policy: {eff!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
