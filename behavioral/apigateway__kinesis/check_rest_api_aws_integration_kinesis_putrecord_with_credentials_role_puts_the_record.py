"""rest-api-aws-integration-kinesis-putrecord-with-credentials-role-puts-the-record."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rest-api-aws-integration-kinesis-putrecord-with-credentials-role-puts-the-record"

GROUP = "integrations"

SERVICES = ["apigateway", "kinesis"]

_REQUEST_TEMPLATE = (
    '{{"StreamName":"{stream_name}",'
    '"Data":"$util.base64Encode($input.path(\'$.data\'))",'
    '"PartitionKey":"$input.path(\'$.pk\')"}}'
)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A REST API ``AWS`` integration is refused by Kinesis with AccessDeniedException when its
    credentials role grants no PutRecord permission, and the same mapping with a role that does
    grant it puts a record carrying the mapped data and partition key.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-create-api-as-simple-proxy-for-aws-service.html
    """
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-xsvc-reststream-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(lambda: ctx.client("kinesis").delete_stream(StreamName=stream_name))
    summary = _poll_until(
        ctx,
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"stream {stream_name} reaching ACTIVE",
    )
    stream_arn = summary["StreamARN"]
    shard_ids = _poll_until(
        ctx,
        lambda: _list_shards(kinesis, stream_name),
        lambda shards: shards is not None,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"stream {stream_name} accepting ListShards once ACTIVE",
    )

    credentials_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["kinesis:PutRecord"], "Resource": stream_arn}
            ],
        },
    )
    # A twin role with the same trust policy but no Kinesis permission at all, to prove the
    # denial is attributable to the credentials role, not to the mapping or the integration.
    denied_role_name, denied_role_arn = _create_named_role(ctx, "apigateway.amazonaws.com")

    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-restapi-"), tags=_xsvc_resource_tags()
    )["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))
    root_id = next(
        item["id"] for item in ag.get_resources(restApiId=api_id)["items"] if item["path"] == "/"
    )
    template = _REQUEST_TEMPLATE.format(stream_name=stream_name)

    def _add_put_method(path_part, role_arn):
        resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart=path_part)["id"]
        # The method writes to the stream, so only a SigV4-signed caller of this account reaches it.
        ag.put_method(
            restApiId=api_id, resourceId=resource_id, httpMethod="POST", authorizationType="AWS_IAM"
        )
        ag.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            type="AWS",
            integrationHttpMethod="POST",
            uri=f"arn:aws:apigateway:{ctx.region}:kinesis:action/PutRecord",
            credentials=role_arn,
            requestTemplates={"application/json": template},
            passthroughBehavior="NEVER",
        )
        ag.put_integration_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200",
            selectionPattern="",
        )
        ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="POST", statusCode="200")

    _add_put_method("put", credentials_arn)
    _add_put_method("put-denied", denied_role_arn)
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(
        restApiId=api_id,
        stageName="sim2real",
        deploymentId=deployment_id,
        tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ag.delete_stage(restApiId=api_id, stageName="sim2real")))

    # --- the negative: a credentials role granting no Kinesis permission is refused by Kinesis
    # itself (not by the gateway), naming exactly that role and resource; past IAM's own
    # AssumeRole-propagation window this is deterministic, never transient.
    denied_url = f"{ctx.api_url(api_id, 'sim2real')}/put-denied"
    denied_body = json.dumps({"data": "irrelevant", "pk": "irrelevant"}).encode()
    expected_denial = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{denied_role_name}/BackplaneAssumeRoleSession "
        f"is not authorized to perform: kinesis:PutRecord on resource: {stream_arn} because no "
        f"identity-based policy allows the kinesis:PutRecord action"
    )
    _, denied_text = _poll_http(
        ctx,
        denied_url,
        body=denied_body,
        headers={"Content-Type": "application/json"},
        accept=lambda s, t: s == 200 and _json_object(t).get("Message") == expected_denial,
        description="POST /put-denied converging on the deterministic AccessDeniedException",
    )
    denied = json.loads(denied_text)
    assert denied.get("__type") == "AccessDeniedException", (
        f"expected __type AccessDeniedException, got {denied.get('__type')!r}: {denied_text[:300]!r}"
    )
    assert denied.get("Message") == expected_denial, (
        f"expected message {expected_denial!r}, got {denied.get('Message')!r}"
    )

    # --- the positive control: the role that does grant kinesis:PutRecord puts the record.
    data_marker = ctx.unique_name("sim2real-xsvc-restdata-")
    partition_key = ctx.unique_name("sim2real-xsvc-restpk-")
    url = f"{ctx.api_url(api_id, 'sim2real')}/put"
    body = json.dumps({"data": data_marker, "pk": partition_key}).encode()
    # The AWS integration's catch-all response mapping (selectionPattern "") returns HTTP 200
    # for Kinesis's own AccessDeniedException too, while CredentialsArn is still propagating
    # through IAM; retry on that one error body rather than on the HTTP status.
    status, text = _poll_http(
        ctx,
        url,
        body=body,
        headers={"Content-Type": "application/json"},
        accept=lambda s, t: s == 200 and "AccessDeniedException" not in t,
        description="POST /put reaching the REST API's AWS integration to Kinesis",
    )
    assert status == 200, f"expected 200 from the AWS integration, got {status}: {text[:300]!r}"
    put_result = json.loads(text)
    assert put_result.get("ShardId") and put_result.get("SequenceNumber"), (
        f"expected a PutRecord-shaped response with ShardId and SequenceNumber, got {text[:300]!r}"
    )

    record = _read_record_at(
        ctx, kinesis, stream_name, shard_ids, put_result["SequenceNumber"], timeout_s=60.0
    )
    assert record["Data"].decode("utf-8") == data_marker, (
        f"the record landed on the stream must carry the mapped Data {data_marker!r}, got "
        f"{record['Data']!r}"
    )
    assert record["PartitionKey"] == partition_key, (
        f"the record landed on the stream must carry the mapped PartitionKey {partition_key!r}, "
        f"got {record['PartitionKey']!r}"
    )


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _json_object(text):
    """``text`` parsed as a JSON object, or {} when it is not one."""
    try:
        value = json.loads(text)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _list_shards(kinesis, stream_name):
    """Shard ids, or None while the stream briefly refuses ListShards right after reaching
    ACTIVE on DescribeStreamSummary (ResourceInUseException/CREATING)."""
    try:
        return [s["ShardId"] for s in kinesis.list_shards(StreamName=stream_name)["Shards"]]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceInUseException":
            return None
        raise


def _read_record_at(ctx, kinesis, stream_name, shard_ids, sequence_number, *, timeout_s):
    """The record at exactly ``sequence_number`` on whichever of ``shard_ids`` encodes it."""
    iterator = None
    for shard_id in shard_ids:
        try:
            iterator = kinesis.get_shard_iterator(
                StreamName=stream_name,
                ShardId=shard_id,
                ShardIteratorType="AT_SEQUENCE_NUMBER",
                StartingSequenceNumber=sequence_number,
            )["ShardIterator"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidArgumentException":
                raise
    assert iterator is not None, f"{sequence_number!r} matched none of {shard_ids!r}"
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        page = kinesis.get_records(ShardIterator=iterator, Limit=10)
        for rec in page["Records"]:
            if rec["SequenceNumber"] == sequence_number:
                return rec
        iterator = page["NextShardIterator"]
        if not page["Records"]:
            time.sleep(2)
    raise TimeoutError(f"the record at {sequence_number!r} never appeared on {shard_ids!r}")


def _budget_s(ctx, want_s):
    """``want_s`` capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return want_s if left is None else max(1.0, min(want_s, left - 10.0))


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _signed_post(ctx, url, *, body, headers, timeout_s=20):
    """(status, text) of one POST SigV4-signed for execute-api; status None on a transport error."""
    creds = ctx.client("sts")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method="POST", url=url, data=body, headers=headers)
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    raw = urllib.request.Request(url, data=body, method="POST", headers=dict(req.headers))
    try:
        with urllib.request.urlopen(
            raw, timeout=timeout_s, context=_ssl_context(ctx.http_verify)
        ) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except OSError:
        return None, ""


def _poll_http(
    ctx, url, *, body, headers, accept, timeout_s=90.0, interval_s=3.0, description="invoke URL"
):
    """Signed POSTs until ``accept(status, text)``; return (status, text). TimeoutError otherwise."""
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        last = _signed_post(ctx, url, body=body, headers=headers)
        if accept(*last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(
        f"{description} ({url}) never reached an accepted status within {budget:.0f}s. "
        f"Last: {last[0]} {last[1][:300]!r}"
    )


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {budget:.0f}s. Last result: {last!r}")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, trust_service, inline_policy=None):
    return _create_named_role(ctx, trust_service, inline_policy)[1]


def _create_named_role(ctx, trust_service, inline_policy=None):
    """(RoleName, Arn) of a freshly created role trusting ``trust_service``."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-xsvc-role-{trust_service.split('.')[0]}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return role_name, resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
