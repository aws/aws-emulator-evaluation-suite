"""cfn-cloudfront-distribution-in-place-update-serves-new-root-object-then-not-found."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from xml.etree import ElementTree

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cloudfront-distribution-in-place-update-serves-new-root-object-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront", "s3"]

#: A distribution's create, update and disable-then-delete each take minutes on CloudFront;
#: the cap only stops a hung poll.
_STACK_CAP_S = 1800.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1700.0
_GONE_CAP_S = 300.0
#: A deployed distribution can take a few minutes to serve its new config from every edge.
_SERVE_CAP_S = 600.0
_POLL_S = 2.0
_SERVE_POLL_S = 5.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: CloudFront's refusal of a distribution that no longer exists.
_NOT_FOUND = ("NoSuchDistribution", "The specified distribution does not exist.")

#: S3's (Code, Message) for an unsigned read of an object no policy grants to anonymous callers.
_DIRECT_REFUSED = ("AccessDenied", "Access Denied")

#: Non-sensitive test objects: the only content the distribution ever serves.
_FIRST_KEY, _FIRST_BODY = "first.html", b"sim2real first root object\n"
_SECOND_KEY, _SECOND_BODY = "second.html", b"sim2real second root object\n"


def _template(comment: str, root_object: str, cache_policy_id: str) -> str:
    """A private bucket served only through the distribution's origin access control."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketEncryption": {
                            "ServerSideEncryptionConfiguration": [
                                {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                            ]
                        },
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "BlockPublicPolicy": True,
                            "IgnorePublicAcls": True,
                            "RestrictPublicBuckets": True,
                        },
                    },
                },
                "Oac": {
                    "Type": "AWS::CloudFront::OriginAccessControl",
                    "Properties": {
                        "OriginAccessControlConfig": {
                            "Name": {"Fn::Sub": "${AWS::StackName}-oac"},
                            "OriginAccessControlOriginType": "s3",
                            "SigningBehavior": "always",
                            "SigningProtocol": "sigv4",
                        }
                    },
                },
                # No property of a distribution is create-only, so no update replaces it.
                "Distribution": {
                    "Type": "AWS::CloudFront::Distribution",
                    "Properties": {
                        "DistributionConfig": {
                            "Enabled": True,
                            "Comment": comment,
                            "DefaultRootObject": root_object,
                            "PriceClass": "PriceClass_100",
                            "Origins": [
                                {
                                    "Id": "s3origin",
                                    "DomainName": {"Fn::GetAtt": ["Bucket", "RegionalDomainName"]},
                                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                                    "OriginAccessControlId": {"Fn::GetAtt": ["Oac", "Id"]},
                                }
                            ],
                            "DefaultCacheBehavior": {
                                "TargetOriginId": "s3origin",
                                "ViewerProtocolPolicy": "redirect-to-https",
                                "CachePolicyId": cache_policy_id,
                                "AllowedMethods": ["GET", "HEAD"],
                            },
                        },
                    },
                },
                "BucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "Properties": {
                        "Bucket": {"Ref": "Bucket"},
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AllowThisDistributionOnly",
                                    "Effect": "Allow",
                                    "Principal": {"Service": "cloudfront.amazonaws.com"},
                                    "Action": "s3:GetObject",
                                    "Resource": {"Fn::Sub": "${Bucket.Arn}/*"},
                                    "Condition": {
                                        "StringEquals": {
                                            "AWS:SourceArn": {
                                                "Fn::Sub": "arn:${AWS::Partition}:cloudfront::"
                                                "${AWS::AccountId}:distribution/${Distribution}"
                                            }
                                        }
                                    },
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "DistributionRef": {"Value": {"Ref": "Distribution"}},
                "DistributionId": {"Value": {"Fn::GetAtt": ["Distribution", "Id"]}},
                "DomainName": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}},
                "BucketName": {"Value": {"Ref": "Bucket"}},
                "BucketDomainName": {"Value": {"Fn::GetAtt": ["Bucket", "RegionalDomainName"]}},
                "OacId": {"Value": {"Fn::GetAtt": ["Oac", "Id"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation distribution reads back as templated and serves its bucket's root object.

    A Comment and DefaultRootObject change keeps the distribution and serves the new root object;
    no property forces a replacement; the bucket refuses direct reads; delete: NoSuchDistribution.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudfront-distribution.html
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-cfncfd-stack-")
    first_comment = f"sim2real {stack_name} one"
    second_comment = f"sim2real {stack_name} two"
    cache_policy_id = _managed_cache_policy(cf, "Managed-CachingDisabled")
    ref = {"stack": stack_name}
    bucket = {}

    # Every teardown wait shares one deadline (limit), which the body's deadline does not bound.
    limit: dict = {}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))
    # CloudFormation refuses to delete a bucket that holds objects, so it is emptied first (LIFO).
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket.get("name")))

    # ---- 1. create: CloudFormation's view, CloudFront's view, the root object served
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first_comment, _FIRST_KEY, cache_policy_id),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = ref["stack"].split(":")[1]
    out = _outputs(stack)
    bucket["name"] = out["BucketName"]
    dist_id = _physical_ids(cfn, ref["stack"])["Distribution"]
    assert (out["DistributionRef"], out["DistributionId"]) == (dist_id, dist_id), (
        f"Ref and GetAtt Id must be the physical id {dist_id!r}, outputs {out!r}"
    )
    arn = f"arn:{partition}:cloudfront::{ctx.account}:distribution/{dist_id}"
    want = _want_config(first_comment, _FIRST_KEY, cache_policy_id, out)
    _assert_distribution(ctx, cf, dist_id, arn, out["DomainName"], want)
    s3.put_object(
        Bucket=out["BucketName"], Key=_FIRST_KEY, Body=_FIRST_BODY, ContentType="text/html"
    )
    s3.put_object(
        Bucket=out["BucketName"], Key=_SECOND_KEY, Body=_SECOND_BODY, ContentType="text/html"
    )
    _assert_serves(ctx, out["DomainName"], _FIRST_BODY)
    # The bucket grants only this distribution: an unsigned read straight from S3 is refused.
    # The bucket's regional domain name is the S3 host CloudFormation published for its partition.
    direct = f"{ctx.endpoint_url(out['BucketDomainName']).rstrip('/')}/{_FIRST_KEY}"
    status, body = _http_get(direct, {}, ctx.http_verify)
    got = (status, _s3_error(body))
    assert got == (403, _DIRECT_REFUSED), (
        f"an unsigned GET of {direct} must be refused with (403, {_DIRECT_REFUSED!r}), got {got!r}"
    )

    # ---- 2. in-place: a new Comment and DefaultRootObject, the same distribution
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second_comment, _SECOND_KEY, cache_policy_id),
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Distribution"] == dist_id, (
        "an in-place update keeps the distribution"
    )
    _assert_in_place(
        _rows(_events(cfn, ref["stack"]), seen, "Distribution"), dist_id, "Distribution"
    )
    assert _outputs(stack) == out, (
        f"outputs after the in-place update {_outputs(stack)!r}, was {out!r}"
    )
    want = _want_config(second_comment, _SECOND_KEY, cache_policy_id, out)
    _assert_distribution(ctx, cf, dist_id, arn, out["DomainName"], want)
    _assert_serves(ctx, out["DomainName"], _SECOND_BODY)

    # ---- 3. no replacement step: every DistributionConfig property updates without one.

    # ---- 4. delete: CloudFormation disables, then deletes the distribution
    _empty_bucket(s3, out["BucketName"])
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(ctx, lambda: cf.get_distribution(Id=dist_id), _NOT_FOUND[0], dist_id)
    assert got == _NOT_FOUND, f"GetDistribution after the stack delete answered {got!r}"


def _managed_cache_policy(cf, name: str) -> str:
    """The id of the AWS managed cache policy *name*, read from CloudFront's own list."""
    items, marker = [], None
    while True:
        page = cf.list_cache_policies(Type="managed", **({"Marker": marker} if marker else {}))
        items += page["CachePolicyList"].get("Items", [])
        marker = page["CachePolicyList"].get("NextMarker")
        if not marker:
            break
    ids = [
        p["CachePolicy"]["Id"]
        for p in items
        if p["CachePolicy"]["CachePolicyConfig"]["Name"] == name
    ]
    assert len(ids) == 1, f"precondition: exactly one managed cache policy {name!r}, got {ids!r}"
    return ids[0]


def _want_config(comment: str, root_object: str, cache_policy_id: str, out: dict) -> tuple:
    return (
        True,
        comment,
        root_object,
        "PriceClass_100",
        [("s3origin", out["BucketDomainName"], out["OacId"], "")],
        ("s3origin", "redirect-to-https", cache_policy_id, ["GET", "HEAD"]),
    )


def _config(config: dict) -> tuple:
    behavior = config["DefaultCacheBehavior"]
    return (
        config["Enabled"],
        config["Comment"],
        config.get("DefaultRootObject"),
        config.get("PriceClass"),
        [
            (
                o["Id"],
                o["DomainName"],
                o.get("OriginAccessControlId"),
                o.get("S3OriginConfig", {}).get("OriginAccessIdentity"),
            )
            for o in config["Origins"]["Items"]
        ],
        (
            behavior["TargetOriginId"],
            behavior["ViewerProtocolPolicy"],
            behavior.get("CachePolicyId"),
            sorted(behavior["AllowedMethods"]["Items"]),
        ),
    )


def _assert_distribution(ctx, cf, dist_id: str, arn: str, domain: str, want: tuple) -> None:
    """GetDistribution reports the template's config exactly, on a Deployed distribution.

    The read is polled: a just-changed distribution reads InProgress until every edge has it.
    """
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        dist = cf.get_distribution(Id=dist_id)["Distribution"]
        got = (
            dist["Id"],
            dist["ARN"],
            dist["DomainName"],
            dist["Status"],
            _config(dist["DistributionConfig"]),
        )
        if got == (dist_id, arn, domain, "Deployed", want):
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {dist_id} read Deployed as templated")
            raise AssertionError(
                f"GetDistribution {got!r}, expected {(dist_id, arn, domain, 'Deployed', want)!r}"
            )
        time.sleep(_SERVE_POLL_S)


def _assert_serves(ctx, domain: str, body: bytes) -> None:
    """GET / through the distribution's domain returns the root object's bytes.

    Polled: a deployed change and the bucket policy can take minutes to reach every edge.
    """
    url, headers = ctx.endpoint_route(domain)
    url = url.rstrip("/") + "/"
    timeout = _budget_s(ctx, _SERVE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = _http_get(url, headers, ctx.http_verify)
        if got == (200, body):
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {url} served {body!r}")
            raise AssertionError(f"GET {url} answered {got!r}, expected (200, {body!r})")
        time.sleep(_SERVE_POLL_S)


def _http_get(url: str, headers: dict, verify) -> tuple[int | None, bytes]:
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=15, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        return None, str(exc).encode()


def _s3_error(body: bytes) -> tuple[str | None, str | None] | None:
    """(Code, Message) of an S3 XML error body; None for a body that is not one."""
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return None
    return root.findtext("Code"), root.findtext("Message")


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(
            cafile=verify if isinstance(verify, str) and verify else None
        )
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


def _empty_bucket(s3, name: str | None) -> None:
    """Delete every object in the stack's bucket; a bucket already gone is done."""
    if name is None:
        return
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                errors = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors", [])
                assert not errors, f"DeleteObjects on {name} left {errors!r}"
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. With ctx None (teardown) it is cap_s.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, cap_s), "DELETE_COMPLETE")


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _teardown_stack(cfn, ref: dict, limit: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Every wait shares the one deadline in *limit*, so the whole teardown fits its cap.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"], _remaining(limit))
    _delete_stack(None, cfn, stack["StackId"], _remaining(limit))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
