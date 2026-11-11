"""deleting-referenced-policy-clears-service-effective-policy-values."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleting-referenced-policy-clears-service-effective-policy-values"
GROUP = 'policy-service-consistency'
SERVICES = ['resiliencehubv2']

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "resiliencehub.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _poll(probe, predicate, *, timeout_s=90.0, interval_s=5.0, description=""):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} did not happen within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a referenced Policy succeeds without being blocked by the reference; the
    Service's effectivePolicyValues then clears while its policyArn pointer stays dangling."""
    rh = ctx.client("resiliencehubv2")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-rhv2-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    policy = rh.create_policy(
        name=ctx.unique_name("sim2real-behav-rhv2-pol-"),
        availabilitySlo={"target": 99.9},
    )["policy"]
    policy_arn = policy["policyArn"]
    policy_cleanup_done = {"value": False}

    def _delete_policy_once():
        if policy_cleanup_done["value"]:
            return
        try:
            rh.delete_policy(policyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        policy_cleanup_done["value"] = True

    ctx.on_cleanup(_delete_policy_once)

    def _create_service():
        return rh.create_service(
            name=ctx.unique_name("sim2real-behav-rhv2-svc-"),
            regions=[ctx.region],
            permissionModel={"invokerRoleName": role_name},
            policyArn=policy_arn,
        )

    def _attempt():
        try:
            return _create_service()["service"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    service = _poll(
        _attempt,
        lambda v: not isinstance(v, str),
        timeout_s=90.0,
        interval_s=5.0,
        description="CreateService with a freshly created invoker role becoming assumable",
    )
    service_arn = service["serviceArn"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_service(serviceArn=service_arn), "ResourceNotFoundException"
    ))

    assert service["policyArn"] == policy_arn, (
        f"expected the created service to carry policyArn {policy_arn!r}, got "
        f"{service.get('policyArn')!r}"
    )
    effective = service["effectivePolicyValues"]
    assert effective.get("availabilitySlo", {}).get("value") == 99.9, (
        f"expected effectivePolicyValues.availabilitySlo.value == 99.9 from the attached policy, "
        f"got {effective!r}"
    )

    _delete_policy_once()

    after = rh.get_service(serviceArn=service_arn)["service"]
    assert after["policyArn"] == policy_arn, (
        f"GetService must still report the dangling policyArn {policy_arn!r} after its policy was "
        f"deleted, got {after.get('policyArn')!r}"
    )
    assert after["effectivePolicyValues"] == {}, (
        f"deleting the referenced policy must clear the service's derived effectivePolicyValues "
        f"to an empty object, got {after['effectivePolicyValues']!r}"
    )

    policy_id = policy_arn.rsplit(":", 1)[-1]
    expected_message = f"Policy not found: {policy_id}"
    gone_code, gone_message = None, None
    try:
        rh.get_policy(policyArn=policy_arn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        gone_code, gone_message = err.get("Code"), err.get("Message")
    assert (gone_code, gone_message) == ("ResourceNotFoundException", expected_message), (
        f"the deleted policy must read back as ResourceNotFoundException {expected_message!r}, "
        f"got {gone_code}: {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
