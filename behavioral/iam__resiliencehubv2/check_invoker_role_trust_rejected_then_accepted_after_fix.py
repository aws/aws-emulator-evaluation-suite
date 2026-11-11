"""invoker-role-trust-rejected-then-accepted-after-fix."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoker-role-trust-rejected-then-accepted-after-fix"
GROUP = 'cross-service'
SERVICES = ['iam', 'resiliencehubv2']

_WRONG_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})
_RIGHT_TRUST = json.dumps({
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


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll(probe, predicate, *, timeout_s=90.0, interval_s=5.0, description=""):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} did not happen within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService refuses a role whose trust policy names the wrong principal, and the
    identical call succeeds once the SAME role's trust policy is rewritten to trust resiliencehub."""
    iam = ctx.client("iam")
    rh = ctx.client("resiliencehubv2")

    role_name = ctx.unique_name("sim2real-xsvc-rhv2-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_WRONG_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    def _attempt_create():
        try:
            return rh.create_service(
                name=ctx.unique_name("sim2real-xsvc-rhv2-svc-"),
                regions=[ctx.region],
                permissionModel={"invokerRoleName": role_name},
            )["service"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")

    # IAM propagation can delay even the FIRST answer by a few seconds; a quota/propagation
    # ValidationException about assumability must keep failing with the same shape, so poll only
    # until a stable refusal is observed, then assert its exact content.
    refusal = _poll(
        _attempt_create,
        lambda v: isinstance(v, tuple),
        timeout_s=60.0,
        interval_s=5.0,
        description="CreateService answering with a refusal rather than a client error",
    )
    code, message = refusal
    assert code == "ValidationException", (
        f"a role trusting lambda.amazonaws.com, not resiliencehub, must be refused with "
        f"ValidationException, got {code}: {message!r}"
    )
    assert message == (
        f"Cannot assume invoker role '{role_name}'. Ensure the role exists and its trust policy "
        f"allows access."
    ), f"unexpected message {message!r}"

    # Break exactly one thing: rewrite the SAME role's trust policy to trust resiliencehub.
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=_RIGHT_TRUST)
    trust = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert trust["Statement"][0]["Principal"]["Service"] == "resiliencehub.amazonaws.com", (
        f"expected the role's trust policy to name resiliencehub.amazonaws.com before its effect "
        f"on CreateService is asserted, got {trust!r}"
    )

    service = _poll(
        _attempt_create,
        lambda v: not isinstance(v, tuple),
        timeout_s=90.0,
        interval_s=5.0,
        description="CreateService succeeding once the role's trust policy allows resiliencehub",
    )
    service_arn = service["serviceArn"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_service(serviceArn=service_arn), "ResourceNotFoundException"
    ))
    assert service["permissionModel"]["invokerRoleName"] == role_name, (
        f"expected the created service's invokerRoleName to be {role_name!r}, got "
        f"{service['permissionModel']['invokerRoleName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
