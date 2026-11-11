"""bulk-thing-registration-task-registers-things-from-s3."""
from __future__ import annotations

import json
import time
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bulk-thing-registration-task-registers-things-from-s3"
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
    """Retry StartThingRegistrationTask while a fresh role is not yet assumable: the call
    test-assumes roleArn synchronously and fails with "Cannot assume provided role" until IAM
    propagates it."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return iot.start_thing_registration_task(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
            if "assume" in msg.lower():
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc!r}")


@tags("axis:happy-path", "cap:c3", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartThingRegistrationTask reads a newline-delimited JSON file from S3 through a role: the
    task completes, every listed thing exists, and the task's RESULTS report names them."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    iot = ctx.client("iot")

    bucket = ctx.unique_name("sim2real-iot-bulk-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    thing_names = [ctx.unique_name("sim2real-bulk-thing-") for _ in range(2)]
    key = "input.jsonl"
    body = "\n".join(json.dumps({"ThingName": name}) for name in thing_names) + "\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    role_name = ctx.unique_name("sim2real-iot-bulk-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "iot-bulk"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTThingsRegistration"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    inline_policy_name = "sim2real-s3-read"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{key}"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    template_body = json.dumps(
        {
            "Parameters": {"ThingName": {"Type": "String"}},
            "Resources": {
                "thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": {"Ref": "ThingName"}}}
            },
        }
    )

    resp = _start_task_with_role_propagation_retry(
        iot, templateBody=template_body, inputFileBucket=bucket, inputFileKey=key, roleArn=role_arn
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
        f"task {task_id} ended in status {desc.get('status') if desc else None!r}, "
        f"expected 'Completed' (desc={desc!r})"
    )
    assert desc["successCount"] == len(thing_names), (
        f"successCount {desc['successCount']!r} != {len(thing_names)} things in the input file"
    )
    assert desc["failureCount"] == 0, f"failureCount {desc['failureCount']!r}, expected 0"

    def _cleanup_thing(name: str) -> None:
        try:
            iot.delete_thing(thingName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    for name in thing_names:
        ctx.on_cleanup(lambda name=name: _cleanup_thing(name))
        described = iot.describe_thing(thingName=name)
        assert described["thingName"] == name, f"describe_thing returned {described!r} for {name!r}"

    reports = iot.list_thing_registration_task_reports(taskId=task_id, reportType="RESULTS")
    links = reports.get("resourceLinks", [])
    assert links, f"task {task_id} completed with no RESULTS report links: {reports!r}"
    reported_things = set()
    for url in links:
        _url, _route = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=15) as resp:  # noqa: S310 - IoT-minted presigned URL
            for line in resp.read().decode().splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                thing_arn = record.get("response", {}).get("ResourceArns", {}).get("thing", "")
                if thing_arn:
                    reported_things.add(thing_arn.rsplit("/", 1)[-1])
    assert set(thing_names) <= reported_things, (
        f"success report named {sorted(reported_things)}, expected it to include {sorted(thing_names)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
