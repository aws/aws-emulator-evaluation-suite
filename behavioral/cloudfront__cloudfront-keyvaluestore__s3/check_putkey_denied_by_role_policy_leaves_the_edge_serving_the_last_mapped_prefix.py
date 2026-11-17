"""putkey-denied-by-role-policy-leaves-the-edge-serving-the-last-mapped-prefix."""
from __future__ import annotations

import itertools
import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putkey-denied-by-role-policy-leaves-the-edge-serving-the-last-mapped-prefix"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "cloudfront-keyvaluestore", "iam", "s3", "sts"]

_SEQ = itertools.count()
_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_DATAPLANE_TAG = "ROUTING_DATAPLANE_UNREACHABLE"

# cloudfront-js-2.0, viewer-request: the same key-to-prefix lookup the routing check performs, with
# no fallback branch -- this check only ever queries a key that is present.
_FUNCTION_CODE = """
import cf from 'cloudfront';
const store = cf.kvs();
async function handler(event) {
    var request = event.request;
    var tenant = request.querystring.tenant.value;
    var prefix = await store.get(tenant);
    request.uri = '/' + prefix + '/page.txt';
    return request;
}
"""


def _wait_until(read, satisfied, *, budget_s, interval_s, label):
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = read()
        if satisfied(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{label} did not happen within {budget_s}s; last observed {last!r}")


def _edge_get(url, satisfied, label, *, headers, verify, budget_s=240.0):
    """GET ``url`` until ``satisfied``; a transport error while the edge propagates is retried."""
    errors = []

    def fetch():
        try:
            return requests.get(url, headers=headers, timeout=15, verify=verify)
        except requests.RequestException as exc:
            errors.append(exc)
            return None

    try:
        return _wait_until(fetch, lambda r: r is not None and satisfied(r), budget_s=budget_s,
                           interval_s=5, label=label)
    except AssertionError as exc:
        tail = f" (last transport error: {errors[-1]!r})" if errors else ""
        raise AssertionError(f"{_DATAPLANE_TAG}: {exc}{tail}") from exc


def _until_deployed(cf, dist_id):
    status = _wait_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed", budget_s=1200, interval_s=15,
        label=f"distribution {dist_id} reaching Deployed",
    )
    assert status == "Deployed", f"distribution {dist_id} status is {status!r}"


def _disable_and_delete_distribution(cf, dist_id):
    try:
        current = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    config, etag = current["DistributionConfig"], current["ETag"]
    if config["Enabled"]:
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
    _until_deployed(cf, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_function_once_unreferenced(cf, name, *, budget_s=300.0):
    deadline = time.monotonic() + budget_s
    while True:
        try:
            etag = cf.describe_function(Name=name)["ETag"]
            cf.delete_function(Name=name, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchFunctionExists":
                return
            if code != "FunctionInUse" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _delete_kvs_once_unreferenced(cf, name, *, budget_s=300.0):
    deadline = time.monotonic() + budget_s
    while True:
        try:
            etag = cf.describe_key_value_store(Name=name)["ETag"]
            cf.delete_key_value_store(Name=name, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFound":
                return
            if code != "CannotDeleteEntityWhileInUse" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _delete_oac(cf, oac_id):
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchOriginAccessControl":
            return
        raise
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _empty_and_delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objects = [{"Key": item["Key"]} for item in page.get("Contents", [])]
            if objects:
                failures = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": objects}
                ).get("Errors")
                assert not failures, f"DeleteObjects left {failures!r} undeleted in {bucket!r}"
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _drop_inline_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, iam, account_id, name_suffix, statements):
    """A role trusting this account's root, carrying exactly ``statements`` from creation --
    its permissions never change after this call, so using it needs no propagation beyond the
    role's own first use."""
    name = ctx.unique_name(f"sim2real-routing-{name_suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_name = "sim2real-kvs-access"
    iam.put_role_policy(RoleName=name, PolicyName=policy_name,
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(lambda: _drop_inline_policy(iam, name, policy_name))
    return name, role_arn


def _assumed_kvs_client(ctx, role_arn, session_name):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 120.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise last_exc
    return ctx.client("cloudfront-keyvaluestore", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _put_through(client, store_arn, key, value):
    """One PutKey (current ETag read first); returns the response."""
    etag = client.describe_key_value_store(KvsARN=store_arn)["ETag"]
    return client.put_key(KvsARN=store_arn, Key=key, Value=value, IfMatch=etag)


def _put_succeeds(client, store_arn, key, value) -> bool:
    try:
        _put_through(client, store_arn, key, value)
        return True
    except ClientError:
        return False


def _put_refusal(client, store_arn, key, value):
    """The refusal's ``(code, message)``; raises naming the response if the call succeeds."""
    try:
        result = _put_through(client, store_arn, key, value)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected PutKey to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A role whose policy explicitly denies cloudfront-keyvaluestore:PutKey cannot retarget a
    prefix mapping the edge reads; the edge keeps serving the last applied prefix, and a second,
    otherwise identical role that allows PutKey retargets it and the edge follows.
    """
    cf = ctx.client("cloudfront")
    kvs = ctx.client("cloudfront-keyvaluestore")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    store_name = ctx.unique_name("sim2real-routing-noperm-kvs-")
    store_arn = cf.create_key_value_store(
        Name=store_name, Comment="sim2real putkey-denied routing map",
    )["KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _delete_kvs_once_unreferenced(cf, store_name))
    status = _wait_until(
        lambda: cf.describe_key_value_store(Name=store_name)["KeyValueStore"]["Status"],
        lambda s: s == "READY", budget_s=300, interval_s=5,
        label=f"key value store {store_name} reaching READY",
    )
    assert status == "READY", f"key value store {store_name} status is {status!r}"

    tenant_key = "contoso-ltd"
    prefix_a, prefix_b = "region-west", "region-east"
    body_a = b"sim2real object served from region-west"
    body_b = b"sim2real object served from region-east"
    kvs.put_key(
        KvsARN=store_arn, Key=tenant_key, Value=prefix_a,
        IfMatch=kvs.describe_key_value_store(KvsARN=store_arn)["ETag"],
    )

    bucket = ctx.unique_name("sim2real-routing-noperm-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    for prefix, body in ((prefix_a, body_a), (prefix_b, body_b)):
        s3.put_object(Bucket=bucket, Key=f"{prefix}/page.txt", Body=body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-routing-noperm-oac-"),
        "Description": "sim2real putkey-denied origin lock",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    fn_name = ctx.unique_name("sim2real-routing-noperm-fn-")
    created_fn = cf.create_function(
        Name=fn_name,
        FunctionConfig={
            "Comment": "sim2real putkey-denied routing",
            "Runtime": "cloudfront-js-2.0",
            "KeyValueStoreAssociations": {"Quantity": 1, "Items": [{"KeyValueStoreARN": store_arn}]},
        },
        FunctionCode=_FUNCTION_CODE.encode(),
    )
    ctx.on_cleanup(lambda: _delete_function_once_unreferenced(cf, fn_name))
    published = cf.publish_function(Name=fn_name, IfMatch=created_fn["ETag"])
    fn_meta = published["FunctionSummary"]["FunctionMetadata"]
    assert fn_meta["Stage"] == "LIVE", f"PublishFunction left the function at {fn_meta['Stage']!r}"
    fn_arn = fn_meta["FunctionARN"]

    dist_config = {
        "CallerReference": f"sim2real-routing-noperm-{ctx.unique_name('d')}-{next(_SEQ)}",
        "Comment": "sim2real putkey-denied routing",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "sim2real-s3-origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "sim2real-s3-origin",
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
            "FunctionAssociations": {
                "Quantity": 1,
                "Items": [{"FunctionARN": fn_arn, "EventType": "viewer-request"}],
            },
        },
    }
    created_dist = cf.create_distribution(DistributionConfig=dist_config)["Distribution"]
    dist_id, dist_domain, dist_arn = (
        created_dist["Id"], created_dist["DomainName"], created_dist["ARN"],
    )
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))
    _until_deployed(cf, dist_id)
    edge, route_headers = ctx.endpoint_route(dist_domain)
    route_url = f"{edge}/page.txt?tenant={tenant_key}"

    baseline = _edge_get(route_url, lambda r: r.status_code == 200 and r.content == body_a,
                         f"the edge serving the initial mapping {prefix_a!r}",
                         headers=route_headers, verify=ctx.http_verify)
    assert baseline.content == body_a, f"before either role exists, edge served {baseline.content!r}"

    # Two roles, each carrying its full, final policy from creation: the one under test denies
    # cloudfront-keyvaluestore:PutKey from the start, so there is no allow-to-deny transition to race.
    read_only_statement = {"Effect": "Allow", "Action": "cloudfront-keyvaluestore:DescribeKeyValueStore",
                           "Resource": store_arn}
    denied_role, denied_role_arn = _create_role(
        ctx, iam, account_id, "noperm-role",
        [read_only_statement,
         {"Effect": "Deny", "Action": "cloudfront-keyvaluestore:PutKey", "Resource": store_arn}],
    )
    allowed_role, allowed_role_arn = _create_role(
        ctx, iam, account_id, "perm-role",
        [read_only_statement,
         {"Effect": "Allow", "Action": "cloudfront-keyvaluestore:PutKey", "Resource": store_arn}],
    )
    denied_client = _assumed_kvs_client(ctx, denied_role_arn, "sim2real-noperm-session")
    allowed_client = _assumed_kvs_client(ctx, allowed_role_arn, "sim2real-perm-session")

    # Bounded retry absorbs only the brand-new role's own propagation (a read its policy already
    # allows); once that succeeds the role's full policy, deny included, is visible to this path.
    _wait_until(
        lambda: _describe_ok(denied_client, store_arn),
        lambda ok: ok, budget_s=90, interval_s=3,
        label="the no-PutKey role's own policy propagating so DescribeKeyValueStore succeeds",
    )
    denied_code, denied_message = _put_refusal(denied_client, store_arn, tenant_key, prefix_b)
    assert denied_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a role with no PutKey grant, got {denied_code!r}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{denied_role}/sim2real-noperm-session is "
        f"not authorized to perform: cloudfront-keyvaluestore:PutKey on resource: {store_arn} "
        f"with an explicit deny in an identity-based policy"
    )
    assert denied_message == expected_message, f"expected {expected_message!r}, got {denied_message!r}"

    # Effect absent: the refused PutKey is the only write attempted against this key since the
    # baseline read, so a single independent read already settles it -- nothing else could have
    # changed the mapping in between.
    unchanged = kvs.get_key(KvsARN=store_arn, Key=tenant_key)["Value"]
    assert unchanged == prefix_a, (
        f"the mapping is {unchanged!r} after a refused PutKey; expected it to remain {prefix_a!r}"
    )
    still_served = _edge_get(route_url, lambda r: r.status_code == 200, "the edge answering after "
                             "the refused retarget", headers=route_headers,
                             verify=ctx.http_verify)
    assert still_served.content == body_a, (
        f"after the refused retarget, the edge served {still_served.content!r}, expected the "
        f"still-mapped {body_a!r}"
    )

    # Twin control, same instant setup: an otherwise identical role that DOES hold PutKey succeeds
    # at the exact same retarget, proving the store, function and edge all work.
    _wait_until(
        lambda: _put_succeeds(allowed_client, store_arn, tenant_key, prefix_b),
        lambda ok: ok, budget_s=90, interval_s=3,
        label="the PutKey-allowed role's own policy propagating so PutKey succeeds",
    )
    served_by_twin = _edge_get(
        route_url, lambda r: r.status_code == 200 and r.content == body_b,
        f"the edge converging on {prefix_b!r} after the permitted role's retarget",
        headers=route_headers, verify=ctx.http_verify,
    )
    assert served_by_twin.content == body_b, (
        f"the PutKey-allowed role's retarget succeeded but the edge served "
        f"{served_by_twin.content!r}, expected {body_b!r}"
    )


def _describe_ok(client, store_arn) -> bool:
    try:
        client.describe_key_value_store(KvsARN=store_arn)
        return True
    except ClientError:
        return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
