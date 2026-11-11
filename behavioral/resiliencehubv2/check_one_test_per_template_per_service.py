"""one-test-per-template-per-service."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "one-test-per-template-per-service"
GROUP = "tests"
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


def _template(ctx) -> str:
    """The AWS-owned dependency-validation test template of this Region."""
    return f"arn:aws:resiliencehub:{ctx.region}:aws:test-template/aws-dependency-validation:rtdep001"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateTest for a template the service already has a test for is refused with
    ConflictException; after DeleteTest the same template creates a new test.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    arn = _create_service(ctx, rh, role)["serviceArn"]
    template = _template(ctx)
    first = rh.create_test(serviceArn=arn, testTemplateArn=template, parameters={"region": [ctx.region]})["test"]
    fid = first["testId"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_test(serviceArn=arn, testId=fid), "ResourceNotFoundException"))

    code, message = _error(lambda: rh.create_test(serviceArn=arn, testTemplateArn=template,
                                                  parameters={"region": [ctx.region]}))
    assert (code, message) == ("ConflictException", (
        "A test already exists for this test template on this service. Only one test can be created "
        "per template on a service. Update the existing test, delete it, or use a different template."
    )), f"second CreateTest: {code}: {message!r}"
    assert [t["testId"] for t in rh.list_tests(serviceArn=arn)["tests"]] == [fid], "still exactly one test"

    rh.delete_test(serviceArn=arn, testId=fid)
    code, message = _error(lambda: rh.get_test(serviceArn=arn, testId=fid))
    assert (code, message) == ("ResourceNotFoundException", (
        "No test was found for the provided test ID and service ARN. Verify that the test ID and service "
        "ARN belong to the same service, then try again."
    )), f"GetTest after delete: {code}: {message!r}"
    second = rh.create_test(serviceArn=arn, testTemplateArn=template, parameters={"region": [ctx.region]})["test"]
    sid = second["testId"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_test(serviceArn=arn, testId=sid), "ResourceNotFoundException"))
    assert sid != fid, "the re-created test must carry a new id"
    assert [t["testId"] for t in rh.list_tests(serviceArn=arn)["tests"]] == [sid], "only the new test is listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
