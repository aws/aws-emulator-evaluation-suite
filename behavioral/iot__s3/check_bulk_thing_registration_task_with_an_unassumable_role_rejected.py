"""bulk-thing-registration-task-with-an-unassumable-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bulk-thing-registration-task-with-an-unassumable-role-rejected"
GROUP = "bulk-provisioning"
SERVICES = ["iot", "s3"]


def _create_bucket(s3, bucket: str, region: str) -> None:
    """us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint
    for; this is a comparison against that documented exception, not a region pin."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)


def _start_task_with_role_propagation_retry(iot, timeout_s: float = 90.0, **kwargs):
    """Retry while a fresh, correctly-trusted role is not yet assumable; used only for the
    positive control, never for the negative call."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.start_thing_registration_task(**kwargs)
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "assume" in msg.lower():
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc!r}")


def _error_code(fn) -> str:
    """Call fn(); return the botocore Error.Code. Raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "")
    raise AssertionError("call that was expected to be rejected unexpectedly succeeded")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message). Raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("call that was expected to be rejected unexpectedly succeeded")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartThingRegistrationTask with a role iot.amazonaws.com cannot assume is rejected every time
    with InvalidRequestException and creates no thing; a role trusting IoT completes the task."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    iot = ctx.client("iot")

    bucket = ctx.unique_name("sim2real-iot-badrole-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    rejected_thing = ctx.unique_name("sim2real-badrole-thing-")
    key = "input.jsonl"
    s3.put_object(Bucket=bucket, Key=key, Body=(json.dumps({"ThingName": rejected_thing}) + "\n").encode())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    template_body = json.dumps(
        {
            "Parameters": {"ThingName": {"Type": "String"}},
            "Resources": {
                "thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": {"Ref": "ThingName"}}}
            },
        }
    )

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    inline_policy_name = "sim2real-s3-read"
    inline_policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{key}"}
            ],
        }
    )

    bad_role_name = ctx.unique_name("sim2real-iot-badrole-role-")
    bad_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(bad_trust_policy),
        Tags=[{"Key": "sim2real", "Value": "iot-badrole"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    iam.attach_role_policy(RoleName=bad_role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=bad_role_name, PolicyArn=managed_policy_arn))
    iam.put_role_policy(RoleName=bad_role_name, PolicyName=inline_policy_name, PolicyDocument=inline_policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=bad_role_name, PolicyName=inline_policy_name))

    errors = set()
    for _ in range(6):
        errors.add(_error(
            lambda: iot.start_thing_registration_task(
                templateBody=template_body, inputFileBucket=bucket, inputFileKey=key, roleArn=bad_role_arn
            )
        ))
        time.sleep(5)  # spaced attempts: the refusal must persist past IAM propagation
    want = {("InvalidRequestException", "Cannot assume provided role")}
    assert errors == want, (
        f"expected every attempt to fail with {want!r}, observed {errors!r}"
    )

    absent = _error(lambda: iot.describe_thing(thingName=rejected_thing))
    want_absent = ("ResourceNotFoundException", f"Thing {ctx.account}:{rejected_thing} not found.")
    assert absent == want_absent, (
        f"expected describe_thing on a never-registered thing to answer {want_absent!r}, got "
        f"{absent!r}"
    )

    good_thing = ctx.unique_name("sim2real-goodrole-thing-")
    good_key = "input-good.jsonl"
    s3.put_object(Bucket=bucket, Key=good_key, Body=(json.dumps({"ThingName": good_thing}) + "\n").encode())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=good_key))

    good_role_name = ctx.unique_name("sim2real-iot-goodrole-role-")
    good_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    good_role_arn = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(good_trust_policy),
        Tags=[{"Key": "sim2real", "Value": "iot-goodrole"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.attach_role_policy(RoleName=good_role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=good_role_name, PolicyArn=managed_policy_arn))
    good_inline_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{good_key}"}
            ],
        }
    )
    iam.put_role_policy(RoleName=good_role_name, PolicyName=inline_policy_name, PolicyDocument=good_inline_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=good_role_name, PolicyName=inline_policy_name))

    resp = _start_task_with_role_propagation_retry(
        iot, templateBody=template_body, inputFileBucket=bucket, inputFileKey=good_key, roleArn=good_role_arn
    )
    task_id = resp["taskId"]

    deadline = time.monotonic() + 120
    desc = None
    while time.monotonic() < deadline:
        desc = iot.describe_thing_registration_task(taskId=task_id)
        if desc["status"] in ("Completed", "Failed", "Cancelled"):
            break
        time.sleep(5)
    assert desc is not None and desc["status"] == "Completed", (
        f"positive-control task {task_id} ended in status "
        f"{desc.get('status') if desc else None!r}, expected 'Completed' (desc={desc!r})"
    )
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=good_thing))
    described = iot.describe_thing(thingName=good_thing)
    assert described["thingName"] == good_thing, (
        f"positive control: describe_thing returned {described!r} for {good_thing!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
