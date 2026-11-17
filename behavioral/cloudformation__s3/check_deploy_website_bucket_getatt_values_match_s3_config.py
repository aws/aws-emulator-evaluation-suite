"""deploy-website-bucket-getatt-values-match-s3-config."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-website-bucket-getatt-values-match-s3-config"
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


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(bucket: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketName": bucket,
            "WebsiteConfiguration": {"IndexDocument": "index.html", "ErrorDocument": "error.html"},
            "Tags": [{"Key": "sim2real", "Value": bucket}]}}},
        "Outputs": {
            "Name": {"Value": {"Ref": "Bucket"}},
            "Arn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
            "Site": {"Value": {"Fn::GetAtt": ["Bucket", "WebsiteURL"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A website bucket's Ref, Arn and WebsiteURL resolve to its name, its S3 ARN and its region's
    website endpoint, and S3 serves the template's index and error documents as its website config."""
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-site-")
    stack_id = cf.create_stack(StackName=bucket, TemplateBody=_template(bucket),
                               Tags=[{"Key": "sim2real", "Value": bucket}])["StackId"]
    ctx.on_cleanup(_delete_stack(cf, stack_id))
    stack = _wait(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"create ended {stack['StackStatus']!r}"
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    assert outputs.get("Name") == bucket, f"Ref output {outputs.get('Name')!r}"
    assert outputs.get("Arn") == f"arn:aws:s3:::{bucket}", f"Arn output {outputs.get('Arn')!r}"
    sites = ctx.s3_website_urls([f"http://{bucket}.s3-website-{ctx.region}.amazonaws.com",
                                 f"http://{bucket}.s3-website.{ctx.region}.amazonaws.com"], bucket)
    assert outputs.get("Site") in sites, f"WebsiteURL output {outputs.get('Site')!r} not in {sites!r}"

    website = s3.get_bucket_website(Bucket=bucket)
    assert website["IndexDocument"] == {"Suffix": "index.html"}, f"index {website.get('IndexDocument')!r}"
    assert website["ErrorDocument"] == {"Key": "error.html"}, f"error document {website.get('ErrorDocument')!r}"
    location = s3.get_bucket_location(Bucket=bucket)["LocationConstraint"] or "us-east-1"
    assert location == ctx.region, f"bucket location {location!r}"

    cf.delete_stack(StackName=stack_id)
    assert _wait(cf, stack_id)["StackStatus"] == "DELETE_COMPLETE", "stack delete did not complete"
    code, msg = _error(lambda: s3.get_bucket_website(Bucket=bucket))
    assert code == "NoSuchBucket", f"deleted bucket lookup code {code!r}"
    assert msg == "The specified bucket does not exist", f"bucket lookup message {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
