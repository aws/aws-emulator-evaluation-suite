"""delete-service-cascades-to-child-resources."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-service-cascades-to-child-resources"
GROUP = 'cascade-delete'
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


def _error(fn):
    """(Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """DeleteService on a service with a function, an assertion and an input source succeeds;
    the function and assertion become unreachable, the input source does not."""
    rh = ctx.client("resiliencehubv2")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-rhv2-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    def _attempt():
        try:
            return rh.create_service(
                name=ctx.unique_name("sim2real-behav-rhv2-svc-"),
                regions=[ctx.region],
                permissionModel={"invokerRoleName": role_name},
            )["service"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    service = _poll(
        _attempt, lambda v: not isinstance(v, str), timeout_s=90.0, interval_s=5.0,
        description="CreateService with a freshly created invoker role becoming assumable",
    )
    service_arn = service["serviceArn"]
    service_deleted = {"value": False}

    def _delete_service_once():
        if service_deleted["value"]:
            return
        try:
            rh.delete_service(serviceArn=service_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        service_deleted["value"] = True

    ctx.on_cleanup(_delete_service_once)

    function = rh.create_service_function(
        serviceArn=service_arn, name="checkout flow", criticality="PRIMARY"
    )["serviceFunction"]
    assertion = rh.create_assertion(
        serviceArn=service_arn, text="Service must survive an AZ outage."
    )["assertion"]
    input_source_id = rh.create_input_source(
        serviceArn=service_arn,
        resourceConfiguration={"resourceTags": [{"key": "app", "values": ["checkout"]}]},
    )["inputSourceId"]
    # An input source outlives its service, so it is NOT reaped by _delete_service_once above;
    # register its own teardown, LIFO before the service delete, using the still-valid pre-delete
    # ARN (DeleteInputSource keeps accepting the dead ARN after the service is gone).
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_input_source(serviceArn=service_arn, inputSourceId=input_source_id),
        "ResourceNotFoundException",
    ))

    # Before the delete, every child is visible through the parent.
    before_functions = [f["serviceFunctionId"] for f in rh.list_service_functions(
        serviceArn=service_arn)["serviceFunctions"]]
    assert function["serviceFunctionId"] in before_functions, (
        f"expected {function['serviceFunctionId']!r} in {before_functions!r} before deletion"
    )
    before_assertions = [a["assertionId"] for a in rh.list_assertions(
        serviceArn=service_arn)["assertions"]]
    assert assertion["assertionId"] in before_assertions, (
        f"expected {assertion['assertionId']!r} in {before_assertions!r} before deletion"
    )
    before_sources = [s["inputSourceId"] for s in rh.list_input_sources(
        serviceArn=service_arn)["inputSourceSummaries"]]
    assert input_source_id in before_sources, (
        f"expected {input_source_id!r} in {before_sources!r} before deletion"
    )

    _delete_service_once()
    service_id = service_arn.rsplit(":", 1)[-1]
    expected_not_found = f"Service not found: {service_id}"

    # After the delete: the parent and its function/assertion children are gone.
    code, message = _error(lambda: rh.get_service(serviceArn=service_arn))
    assert (code, message) == ("ResourceNotFoundException", expected_not_found), (
        f"GetService on the deleted service must be ResourceNotFoundException {expected_not_found!r}, "
        f"got {code}: {message!r}"
    )
    code, message = _error(lambda: rh.list_service_functions(serviceArn=service_arn))
    assert (code, message) == ("ResourceNotFoundException", expected_not_found), (
        f"ListServiceFunctions on the deleted service must be ResourceNotFoundException "
        f"{expected_not_found!r}, not an empty list, got {code}: {message!r}"
    )
    code, message = _error(lambda: rh.list_assertions(serviceArn=service_arn))
    assert (code, message) == ("ResourceNotFoundException", expected_not_found), (
        f"ListAssertions on the deleted service must be ResourceNotFoundException "
        f"{expected_not_found!r}, got {code}: {message!r}"
    )

    # But the input source is the documented exception: it survives the parent's deletion and
    # stays reachable through the same, now-dead ARN.
    after_sources = [s["inputSourceId"] for s in rh.list_input_sources(
        serviceArn=service_arn)["inputSourceSummaries"]]
    assert input_source_id in after_sources, (
        f"expected the input source {input_source_id!r} to survive the service's deletion and "
        f"still appear in ListInputSources on the dead ARN, got {after_sources!r}"
    )

    rh.delete_input_source(serviceArn=service_arn, inputSourceId=input_source_id)
    after_delete = [s["inputSourceId"] for s in rh.list_input_sources(
        serviceArn=service_arn)["inputSourceSummaries"]]
    assert input_source_id not in after_delete, (
        f"expected {input_source_id!r} to be gone from ListInputSources after an explicit "
        f"DeleteInputSource on the dead ARN, got {after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
