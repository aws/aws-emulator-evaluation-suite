"""test-creation-requires-multi-az-rto-on-services-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-creation-requires-multi-az-rto-on-services-policy"
GROUP = 'policy-service-consistency'
SERVICES = ['resiliencehubv2']

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "resiliencehub.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})
_AZ_RECOVERY_TEMPLATE = "arn:aws:resiliencehub:us-west-2:aws:test-template/aws-az-recovery:rtaz001"


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
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTest for the AZ-recovery template is refused while the service's policy has no
    multi-AZ RTO target, and the identical call succeeds once UpdatePolicy adds one."""
    rh = ctx.client("resiliencehubv2")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-rhv2-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    policy_arn = rh.create_policy(
        name=ctx.unique_name("sim2real-behav-rhv2-pol-"),
        availabilitySlo={"target": 99.9},
    )["policy"]["policyArn"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_policy(policyArn=policy_arn), "ResourceNotFoundException"
    ))

    def _attempt():
        try:
            return rh.create_service(
                name=ctx.unique_name("sim2real-behav-rhv2-svc-"),
                regions=[ctx.region],
                permissionModel={"invokerRoleName": role_name},
                policyArn=policy_arn,
            )["service"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    service = _poll(
        _attempt, lambda v: not isinstance(v, str), timeout_s=90.0, interval_s=5.0,
        description="CreateService with a freshly created invoker role becoming assumable",
    )
    service_arn = service["serviceArn"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_service(serviceArn=service_arn), "ResourceNotFoundException"
    ))

    # The template requires the Availability Zone to impair, as a zone ID; both calls name it.
    zone_id = ctx.client("ec2").describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneId"]
    test_parameters = {"availabilityZone": [zone_id]}

    # The policy has no multi-AZ target: the AZ-recovery template must be refused.
    code, message = _error(lambda: rh.create_test(
        serviceArn=service_arn, testTemplateArn=_AZ_RECOVERY_TEMPLATE,
        parameters=test_parameters,
    ))
    assert code == "ValidationException", (
        f"CreateTest with no multi-AZ RTO on the service's policy must be refused with "
        f"ValidationException, got {code}: {message!r}"
    )
    assert message == (
        "The test template requires a policy with Multi-AZ RTO configured. Configure "
        "Multi-AZ RTO on the service's policy and try again."
    ), f"unexpected message {message!r}"

    # A positive control: ListTests confirms nothing was created by the refused call.
    tests = rh.list_tests(serviceArn=service_arn)["tests"]
    assert tests == [], f"expected no tests after a refused CreateTest, got {tests!r}"

    # Break exactly one thing: add a multi-AZ RTO target to the SAME policy.
    rh.update_policy(
        policyArn=policy_arn,
        multiAz={"rtoInMinutes": 15, "rpoInMinutes": 5, "disasterRecoveryApproach": "WARM_STANDBY"},
    )
    updated = rh.get_policy(policyArn=policy_arn)["policy"]
    assert updated.get("multiAz", {}).get("rtoInMinutes") == 15, (
        f"expected the policy's multiAz.rtoInMinutes to be observably 15 before its effect on "
        f"CreateTest is asserted, got {updated.get('multiAz')!r}"
    )

    # The identical CreateTest call now succeeds, and no test run is ever started.
    test = rh.create_test(
        serviceArn=service_arn, testTemplateArn=_AZ_RECOVERY_TEMPLATE,
        parameters=test_parameters,
    )["test"]
    test_id = test["testId"]
    ctx.on_cleanup(_teardown(
        lambda: rh.delete_test(serviceArn=service_arn, testId=test_id), "ResourceNotFoundException"
    ))
    assert test["testTemplateArn"] == _AZ_RECOVERY_TEMPLATE, (
        f"expected the created test's testTemplateArn to be {_AZ_RECOVERY_TEMPLATE!r}, got "
        f"{test['testTemplateArn']!r}"
    )
    tests = [t["testId"] for t in rh.list_tests(serviceArn=service_arn)["tests"]]
    assert test_id in tests, f"expected {test_id!r} in ListTests after the policy was fixed: {tests!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
