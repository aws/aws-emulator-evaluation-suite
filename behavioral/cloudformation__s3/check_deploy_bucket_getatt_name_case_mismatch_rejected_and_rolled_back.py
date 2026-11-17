"""deploy-bucket-getatt-name-case-mismatch-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-bucket-getatt-name-case-mismatch-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

def _wait(cf, stack_id: str, budget_s: float = 600.0) -> dict:
    """The stack once it leaves every *_IN_PROGRESS state."""
    deadline = time.monotonic() + budget_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {budget_s}s")
        time.sleep(4)


def _delete_stack(cf, stack_id: str):
    """A cleanup that deletes the stack and raises unless it reaches DELETE_COMPLETE."""

    def run_delete() -> None:
        cf.delete_stack(StackName=stack_id)
        status = _wait(cf, stack_id)["StackStatus"]
        if status != "DELETE_COMPLETE":
            raise AssertionError(f"stack delete ended {status!r}")

    return run_delete


def _events(cf, stack_id: str) -> list:
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(bucket: str, attribute: str) -> str:
    """A named bucket outputting Fn::GetAtt ``attribute``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketName": bucket, "Tags": [{"Key": "sim2real", "Value": bucket}]}}},
        "Outputs": {"Site": {"Value": {"Fn::GetAtt": ["Bucket", attribute]}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Fn::GetAtt attribute names are case-sensitive: websiteURL on a bucket fails the create and
    removes the bucket, while WebsiteURL on the same template creates the stack and resolves."""
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stacks = {}
    for attribute in ("WebsiteURL", "websiteURL"):
        key = "exact" if attribute == "WebsiteURL" else "lower"
        name = ctx.unique_name(f"sim2real-behav-att{key}-")
        stack_id = cf.create_stack(StackName=name, TemplateBody=_template(name, attribute),
                                   Tags=[{"Key": "sim2real", "Value": name}])["StackId"]
        ctx.on_cleanup(_delete_stack(cf, stack_id))
        stacks[key] = (name, stack_id)

    bucket, stack_id = stacks["exact"]
    control = _wait(cf, stack_id)
    assert control["StackStatus"] == "CREATE_COMPLETE", f"control stack ended {control['StackStatus']!r}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in control.get("Outputs", [])}
    assert sorted(outputs) == ["Site"], f"control outputs {outputs!r}"
    sites = ctx.s3_website_urls([f"http://{bucket}.s3-website-{ctx.region}.amazonaws.com",
                                 f"http://{bucket}.s3-website.{ctx.region}.amazonaws.com"], bucket)
    assert outputs["Site"] in sites, f"WebsiteURL output {outputs['Site']!r} not in {sites!r}"
    assert s3.head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPStatusCode"] == 200, "control bucket missing"

    bucket, stack_id = stacks["lower"]
    broken = _wait(cf, stack_id)
    assert broken["StackStatus"] == "ROLLBACK_COMPLETE", f"lower-case stack ended {broken['StackStatus']!r}"
    assert "Outputs" not in broken, f"rolled-back stack shows outputs {broken['Outputs']!r}"
    reasons = [e.get("ResourceStatusReason") for e in _events(cf, stack_id)
               if e["LogicalResourceId"] == bucket and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"]
    expected = ("Requested attribute websiteURL does not exist in schema for AWS::S3::Bucket. "
                "Rollback requested by user.")
    assert reasons == [expected], f"rollback reasons {reasons!r}"
    code, msg = _error(lambda: s3.get_bucket_tagging(Bucket=bucket))
    assert code == "NoSuchBucket", f"rolled-back bucket lookup code {code!r}"
    assert msg == "The specified bucket does not exist", f"bucket lookup message {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
