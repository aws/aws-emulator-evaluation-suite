"""effective-policy-values-take-the-strictest-target-across-service-and-journey-policies."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "effective-policy-values-take-the-strictest-target-across-service-and-journey-policies"
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


def _create_system(ctx, rh, **kwargs) -> dict:
    """A system deleted at teardown."""
    system = rh.create_system(name=ctx.unique_name("sim2real-behav-rhv2-sys-"), **kwargs)["system"]
    arn = system["systemArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_system(systemArn=arn), "ResourceNotFoundException"))
    return system


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A service with its own policy, in a user journey with another, derives each effective target
    from whichever policy is strictest: the higher availability SLO, the lower RTO and RPO.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    own = _create_policy(ctx, rh, availabilitySlo={"target": 99.95},
                         multiAz={"rtoInMinutes": 30, "rpoInMinutes": 10,
                                  "disasterRecoveryApproach": "HOT_STANDBY"})
    journey_policy = _create_policy(ctx, rh, availabilitySlo={"target": 99.99},
                                    multiAz={"rtoInMinutes": 15, "rpoInMinutes": 20,
                                             "disasterRecoveryApproach": "HOT_STANDBY"},
                                    multiRegion={"rtoInMinutes": 60, "rpoInMinutes": 15,
                                                 "disasterRecoveryApproach": "PILOT_LIGHT"})
    system = _create_system(ctx, rh)
    journey = rh.create_user_journey(systemArn=system["systemArn"], name="checkout",
                                     policyArn=journey_policy["policyArn"])["userJourney"]
    service = _create_service(ctx, rh, role, policyArn=own["policyArn"])

    alone = service["effectivePolicyValues"]
    assert alone["availabilitySlo"]["value"] == 99.95, f"own policy alone: {alone!r}"
    assert "multiRegionRto" not in alone, f"no multi-Region target exists yet: {alone!r}"

    rh.update_service(serviceArn=service["serviceArn"], associatedSystems=[
        {"systemArn": system["systemArn"], "userJourneyIds": [journey["userJourneyId"]]}])
    merged = rh.get_service(serviceArn=service["serviceArn"])["service"]["effectivePolicyValues"]
    got = {k: (v["value"], v["policyName"]) for k, v in merged.items()
           if k in ("availabilitySlo", "multiAzRto", "multiAzRpo", "multiRegionRto", "multiRegionRpo")}
    want = {
        "availabilitySlo": (99.99, journey_policy["name"]),
        "multiAzRto": (15, journey_policy["name"]),
        "multiAzRpo": (10, own["name"]),
        "multiRegionRto": (60, journey_policy["name"]),
        "multiRegionRpo": (15, journey_policy["name"]),
    }
    assert got == want, f"expected the strictest target per field {want!r}, got {got!r}"

    # Only the service's own policyArn counts as an association of that policy.
    own_count = rh.get_policy(policyArn=own["policyArn"])["policy"]["associatedServiceCount"]
    journey_count = rh.get_policy(policyArn=journey_policy["policyArn"])["policy"]["associatedServiceCount"]
    assert (own_count, journey_count) == (1, 0), (
        f"expected associatedServiceCount (own, journey) == (1, 0), got {(own_count, journey_count)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
