"""create-distribution-rejects-an-oac-lambda-type-on-a-non-lambda-custom-origin."""
from __future__ import annotations

import io
import json
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-distribution-rejects-an-oac-lambda-type-on-a-non-lambda-custom-origin"
GROUP = "origin-access-control"
SERVICES = ["cloudfront", "iam", "lambda"]

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

#: AWS's exact refusal when an origin's OriginAccessControlId names an OAC whose
#: OriginAccessControlOriginType does not match the origin, built from no value this check knows.
_MISMATCH = (
    "IllegalOriginAccessConfiguration",
    "Illegal configuration: The origin type and OAC origin type differ",
)

_FUNCTION_SOURCE = '''\
def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
'''


def _zip_source(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buf.getvalue()


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def expect_error(fn, code: str, message: str):
    """Calls ``fn()``; asserts it raises exactly this code and message. Raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, (
            f"expected {code!r}, got {err['Code']!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == message, (
            f"expected message {message!r} for {code!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused with {code!r}, but it succeeded: {result!r}")


def _distributions(cf) -> list:
    items = []
    paginator = cf.get_paginator("list_distributions")
    for page in paginator.paginate():
        items.extend(page["DistributionList"].get("Items") or [])
    return items


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateDistribution refuses a custom origin naming an OAC of type lambda whose domain is not
    a Lambda function URL host, with IllegalOriginAccessConfiguration and its exact message, and no
    distribution is created.
    """
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-cfmism-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real role for a lambda function URL named by a mismatched OAC",
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    function_name = ctx.unique_name("sim2real-behav-cfmism-fn-")

    def create_function():
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_source(_FUNCTION_SOURCE)},
                Timeout=5,
                Tags={t["Key"]: t["Value"] for t in _TAG_SET},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            return None  # a freshly created role is not yet assumable by Lambda

    deadline = time.monotonic() + 180.0
    created = None
    while time.monotonic() < deadline:
        created = create_function()
        if created is not None:
            break
        time.sleep(2.0)  # IAM propagation: no API reports a role has become assumable yet
    assert created is not None, (
        f"CreateFunction never accepted the freshly created role {role_name} within 180s"
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))

    deadline = time.monotonic() + 180.0
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=function_name)["State"]
        if state == "Active":
            break
        time.sleep(2.0)
    assert state == "Active", f"function {function_name} never reached Active, last state {state!r}"

    function_url = lam.create_function_url_config(
        FunctionName=function_name, AuthType="AWS_IAM")["FunctionUrl"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function_url_config(
        FunctionName=function_name))
    lambda_host = urllib.parse.urlparse(function_url).netloc
    assert lambda_host != "", (
        f"CreateFunctionUrlConfig must return an absolute https URL, got {function_url!r}"
    )

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfmism-oac-"),
        "OriginAccessControlOriginType": "lambda",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    # POSITIVE CONTROLS: both principals exist and are well-formed, so a refusal cannot be a
    # dangling-id error.
    got_oac = cf.get_origin_access_control(Id=oac_id)["OriginAccessControl"]
    assert got_oac["Id"] == oac_id, f"GetOriginAccessControl returned id {got_oac['Id']!r}"
    assert got_oac["OriginAccessControlConfig"]["OriginAccessControlOriginType"] == "lambda", (
        f"OAC origin type is {got_oac['OriginAccessControlConfig']!r}, expected 'lambda'"
    )
    got_fn_url = lam.get_function_url_config(FunctionName=function_name)
    assert got_fn_url["AuthType"] == "AWS_IAM", (
        f"the function URL's AuthType is {got_fn_url['AuthType']!r}, expected AWS_IAM"
    )
    assert urllib.parse.urlparse(got_fn_url["FunctionUrl"]).netloc == lambda_host, (
        f"GetFunctionUrlConfig returned a different host: {got_fn_url['FunctionUrl']!r}"
    )

    # A domain this account owns through nothing but this run — a plain custom HTTP origin, not a
    # Lambda function URL host — paired with an OAC whose type is 'lambda'.
    mismatched_domain = f"{ctx.unique_name('sim2real-behav-cfmism-origin-')}.example.com"
    comment = ctx.unique_name("sim2real-behav-cfmism-dist-")
    config = {
        "CallerReference": comment,
        "Comment": comment,
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "mismatched",
            "DomainName": mismatched_domain,
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                "OriginReadTimeout": 30,
                "OriginKeepaliveTimeout": 5,
            },
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "mismatched",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # managed CachingDisabled
        },
    }

    def _create():
        # If the target wrongly accepts the config, register its teardown BEFORE expect_error
        # raises on the unexpected success, so a leak never depends on which line fails.
        created_dist = cf.create_distribution(DistributionConfig=config)["Distribution"]
        dist_id = created_dist["Id"]
        ctx.on_cleanup(lambda: cf.delete_distribution(
            Id=dist_id, IfMatch=cf.get_distribution(Id=dist_id)["ETag"]))
        return created_dist["Id"]

    expect_error(_create, *_MISMATCH)

    # EFFECT ABSENT: no distribution carries this run's unique comment.
    leaked = [d["Id"] for d in _distributions(cf) if d.get("Comment") == comment]
    assert leaked == [], f"the refused CreateDistribution still produced distributions {leaked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
