"""template-url-summary-cost-and-stack-set."""
from __future__ import annotations

import json
import re
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "template-url-summary-cost-and-stack-set"
GROUP = "template-url"
SERVICES = ["cloudformation", "s3"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 180.0
_DESCRIPTION = "template served from S3"
# EstimateTemplateCost returns an https calculator Url; the estimate id in its fragment is fresh per
# call, so it is pinned by form.
_COST_FRAGMENT_RE = re.compile(r"/estimate\?id=cloudformation/[0-9a-f]{40}")

_BODY = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": _DESCRIPTION,
    "Parameters": {"Label": {"Type": "String", "Default": "blue", "Description": "a label"}},
    "Resources": {
        "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "Topic": {"Type": "AWS::SNS::Topic"},
    },
})


def _bucket(ctx, s3) -> str:
    """A private bucket emptied and deleted in teardown; a failed delete raises."""
    bucket = ctx.unique_name("sim2real-behav-tplurl-")
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
    """DeleteStackSet; a set that is already gone is the only tolerated error."""
    try:
        cf.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTemplateSummary, EstimateTemplateCost and CreateStackSet read a template from a regional
    S3 TemplateURL exactly as from the same TemplateBody; the stack set stores the fetched body, and
    after DeleteStackSet DescribeStackSet is refused with the exact StackSetNotFoundException.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStackSet.html
    """
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="template.json", Body=_BODY.encode(), ContentType="application/json")
    # CloudFormation fetches the template itself, from the regional S3 host it resolves a
    # TemplateURL against, so the URL names that host and never the S3 client's endpoint.
    url = f"https://s3.{ctx.region}.amazonaws.com/{bucket}/template.json"

    by_url = cf.get_template_summary(TemplateURL=url)
    by_body = cf.get_template_summary(TemplateBody=_BODY)
    for field in ("Description", "Parameters", "ResourceTypes", "Version"):
        assert by_url.get(field) == by_body.get(field), (
            f"GetTemplateSummary {field} by URL {by_url.get(field)!r} differs from by body {by_body.get(field)!r}"
        )
    assert by_url["Description"] == _DESCRIPTION, f"Description: {by_url['Description']!r}"
    assert sorted(by_url["ResourceTypes"]) == ["AWS::CloudFormation::WaitConditionHandle", "AWS::SNS::Topic"], (
        f"ResourceTypes: {by_url['ResourceTypes']!r}"
    )

    cost_url = urllib.parse.urlsplit(cf.estimate_template_cost(TemplateURL=url)["Url"])
    cost_body = urllib.parse.urlsplit(cf.estimate_template_cost(TemplateBody=_BODY)["Url"])
    for label, parts in (("URL", cost_url), ("body", cost_body)):
        assert (parts.scheme, bool(parts.netloc)) == ("https", True), (
            f"EstimateTemplateCost by {label} must return an https Url with a host: {parts!r}"
        )
        assert _COST_FRAGMENT_RE.fullmatch(parts.fragment), (
            f"EstimateTemplateCost by {label} Url form: {parts!r}"
        )

    name = ctx.unique_name("sim2real-behav-tplurl-set-")
    created = cf.create_stack_set(StackSetName=name, TemplateURL=url, Tags=_TAGS,
                                  Parameters=[{"ParameterKey": "Label", "ParameterValue": "green"}])
    ctx.on_cleanup(lambda: _delete_stack_set(cf, name))
    assert re.fullmatch(rf"{re.escape(name)}:[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}",
                        created["StackSetId"]), f"StackSetId form: {created['StackSetId']!r}"
    stack_set = cf.describe_stack_set(StackSetName=name)["StackSet"]
    assert stack_set["Status"] == "ACTIVE", f"stack set status: {stack_set['Status']!r}"
    assert json.loads(stack_set["TemplateBody"]) == json.loads(_BODY), "the stack set must store the fetched body"
    # StackSet.Description is the CreateStackSet request's own Description member, never derived
    # from the fetched template's Description; CreateStackSet passed none.
    assert "Description" not in stack_set, f"stack set Description: {stack_set.get('Description')!r}"
    params = {p["ParameterKey"]: p["ParameterValue"] for p in stack_set["Parameters"]}
    assert params == {"Label": "green"}, f"stack set Parameters: {params!r}"

    cf.delete_stack_set(StackSetName=name)
    # A stack set with no stack instances deletes without a DELETED-status window: real AWS takes
    # DescribeStackSet straight from ACTIVE to StackSetNotFoundException, so the only poll target
    # is the not-found error, never an intermediate terminal status.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        try:
            status = cf.describe_stack_set(StackSetName=name)["StackSet"]["Status"]
        except ClientError as exc:
            status = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"stack set {name} still {status!r} after {_DEADLINE_S}s")
        time.sleep(3.0)
    assert status == ("StackSetNotFoundException", f"StackSet {name} not found"), (
        f"a deleted stack set reads as {status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
