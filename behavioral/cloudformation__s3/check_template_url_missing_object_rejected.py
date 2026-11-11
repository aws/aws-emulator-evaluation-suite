"""template-url-missing-object-rejected."""
from __future__ import annotations

import json
import re
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-url-missing-object-rejected"
GROUP = "template-url"
SERVICES = ["cloudformation", "s3"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
# EstimateTemplateCost returns an https calculator Url; the estimate id in its fragment is fresh per
# call, so it is pinned by form.
_COST_FRAGMENT_RE = re.compile(r"/estimate\?id=cloudformation/[0-9a-f]{40}")

_BODY = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
})


def _bucket(ctx, s3) -> str:
    """A private bucket emptied and deleted in teardown; a failed delete raises."""
    bucket = ctx.unique_name("sim2real-behav-tplurl-miss-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # us-east-1 refuses an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def drop() -> None:
        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                        for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if objs:
                    errors = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                    if errors:
                        raise AssertionError(f"DeleteObjects left {errors!r}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(drop)
    return bucket


def _delete_stack_set(cf, name: str) -> None:
    try:
        cf.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An S3 TemplateURL naming a key that does not exist is refused by GetTemplateSummary,
    EstimateTemplateCost and CreateStackSet with the exact S3 fetch error, and no stack set is made,
    while the same three calls accept the URL of the object that does exist.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_GetTemplateSummary.html
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="present.json", Body=_BODY.encode(), ContentType="application/json")

    def url(key: str) -> str:
        # CloudFormation fetches the template itself, from the regional S3 host it resolves a
        # TemplateURL against, so the URL names that host and never the S3 client's endpoint.
        return f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}"

    present, absent = url("present.json"), url("absent.json")
    control = cf.get_template_summary(TemplateURL=present)
    assert control["ResourceTypes"] == ["AWS::CloudFormation::WaitConditionHandle"], (
        f"the control URL must be readable: {control['ResourceTypes']!r}"
    )
    cost = urllib.parse.urlsplit(cf.estimate_template_cost(TemplateURL=present)["Url"])
    assert (cost.scheme, bool(cost.netloc)) == ("https", True), (
        f"EstimateTemplateCost of the present key must return an https Url with a host: {cost!r}"
    )
    assert _COST_FRAGMENT_RE.fullmatch(cost.fragment), (
        f"EstimateTemplateCost of the present key must return a calculator Url: {cost!r}"
    )
    control_set = ctx.unique_name("sim2real-behav-tplurl-ok-set-")
    cf.create_stack_set(StackSetName=control_set, TemplateURL=present, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_stack_set(cf, control_set))
    control_status = cf.describe_stack_set(StackSetName=control_set)["StackSet"]["Status"]
    assert control_status == "ACTIVE", (
        f"CreateStackSet from the present key must make an ACTIVE set, got {control_status!r}"
    )

    s3_fetch_message = f"S3 object does not exist. Bucket: {bucket}, Key: absent.json. Error: NoSuchKey"
    expected = ("ValidationError", s3_fetch_message)
    got = _error(lambda: cf.get_template_summary(TemplateURL=absent))
    assert got == expected, f"GetTemplateSummary of a missing key: got {got!r}"
    got = _error(lambda: cf.estimate_template_cost(TemplateURL=absent))
    assert got == expected, f"EstimateTemplateCost of a missing key: got {got!r}"

    # CreateStackSet proxies through the StackSets control plane, which appends its own
    # (Service: ...; Request ID: <uuid>; Proxy: null) suffix naming an AWS-generated request id.
    stack_set_message_re = re.compile(
        rf"\A{re.escape(s3_fetch_message)} \(Service: AmazonCloudFormation; Status Code: 400; "
        r"Error Code: ValidationError; "
        r"Request ID: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}; Proxy: null\)\Z"
    )
    name = ctx.unique_name("sim2real-behav-tplurl-miss-set-")
    try:
        cf.create_stack_set(StackSetName=name, TemplateURL=absent, Tags=_TAGS)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
    else:
        ctx.on_cleanup(lambda: _delete_stack_set(cf, name))
        raise AssertionError(f"CreateStackSet with a missing TemplateURL created {name}")
    assert got[0] == "ValidationError" and stack_set_message_re.match(got[1]), (
        f"CreateStackSet of a missing key: got {got!r}"
    )
    gone = _error(lambda: cf.describe_stack_set(StackSetName=name))
    assert gone == ("StackSetNotFoundException", f"StackSet {name} not found"), (
        f"a refused CreateStackSet must leave no set; got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
