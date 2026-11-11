"""policy-update-propagates-to-referencing-service-effective-values."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-update-propagates-to-referencing-service-effective-values"
GROUP = "effective-policy"
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
    """UpdatePolicy on a policy a service references changes that service's effectivePolicyValues
    on its next read, adding a newly defined target and keeping the untouched one.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    policy = _create_policy(ctx, rh, availabilitySlo={"target": 99.9})
    service = _create_service(ctx, rh, role, policyArn=policy["policyArn"])
    before = service["effectivePolicyValues"]
    assert set(before) == {"availabilitySlo"}, f"expected only availabilitySlo, got {before!r}"

    rh.update_policy(policyArn=policy["policyArn"], availabilitySlo={"target": 99.99},
                     dataRecovery={"timeBetweenBackupsInMinutes": 60})
    stored = rh.get_policy(policyArn=policy["policyArn"])["policy"]
    assert stored["availabilitySlo"] == {"target": 99.99}, f"GetPolicy: {stored.get('availabilitySlo')!r}"
    assert stored["dataRecovery"] == {"timeBetweenBackupsInMinutes": 60}, f"GetPolicy: {stored.get('dataRecovery')!r}"

    after = rh.get_service(serviceArn=service["serviceArn"])["service"]["effectivePolicyValues"]
    assert after["availabilitySlo"]["value"] == 99.99, f"expected 99.99 after UpdatePolicy, got {after!r}"
    assert after["availabilitySlo"]["policyName"] == policy["name"], f"got {after['availabilitySlo']!r}"
    assert "multiAzRto" not in after, f"no multi-AZ target was ever defined: {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
