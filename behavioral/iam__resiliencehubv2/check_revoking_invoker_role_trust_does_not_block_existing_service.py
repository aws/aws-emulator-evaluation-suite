"""revoking-invoker-role-trust-does-not-block-existing-service."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoking-invoker-role-trust-does-not-block-existing-service"
GROUP = 'cross-service'
SERVICES = ['iam', 'resiliencehubv2']

_ALLOW_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "resiliencehub.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})
_DENY_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Principal": {"Service": "resiliencehub.amazonaws.com"},
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


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Revoking the invoker role's trust policy after a service exists does not block GetService
    or UpdateService on it: assumability is checked only at CreateService time."""
    iam = ctx.client("iam")
    rh = ctx.client("resiliencehubv2")

    role_name = ctx.unique_name("sim2real-xsvc-rhv2-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_ALLOW_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    def _attempt_create():
        try:
            return rh.create_service(
                name=ctx.unique_name("sim2real-xsvc-rhv2-svc-"),
                regions=[ctx.region],
                permissionModel={"invokerRoleName": role_name},
            )["service"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    service = _poll(
        _attempt_create, lambda v: not isinstance(v, str), timeout_s=90.0, interval_s=5.0,
        description="CreateService with a freshly created, correctly trusted invoker role",
    )
    service_arn = service["serviceArn"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_service(serviceArn=service_arn), "ResourceNotFoundException"
    ))

    # Break exactly one thing: deny resiliencehub in the SAME role's trust policy.
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=_DENY_TRUST)
    trust = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert trust["Statement"][0]["Effect"] == "Deny", (
        f"expected the role's trust policy to observably Deny resiliencehub before its effect "
        f"on the service is asserted, got {trust!r}"
    )

    # Poll GetService across the window the denial could propagate in: every observation must
    # keep succeeding, not just a single read taken after a fixed wait.
    deadline = time.monotonic() + 15.0
    read = None
    while True:
        read = rh.get_service(serviceArn=service_arn)["service"]
        assert read["serviceArn"] == service_arn, (
            f"GetService must keep succeeding for the same service while its invoker role's "
            f"trust is denied, got {read!r}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(3)

    updated = rh.update_service(
        serviceArn=service_arn, description="still reachable after trust revoked"
    )["service"]
    assert updated["description"] == "still reachable after trust revoked", (
        f"UpdateService must still succeed after the invoker role's trust was revoked, got "
        f"{updated.get('description')!r}"
    )

    # And the change is durable, not an artifact of one lucky read.
    reread = rh.get_service(serviceArn=service_arn)["service"]
    assert reread["description"] == "still reachable after trust revoked", (
        f"a second, independent GetService must see the same update, got "
        f"{reread.get('description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
