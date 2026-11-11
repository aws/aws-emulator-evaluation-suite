"""aws-proxy-subtype-kinesis-putrecord-required-parameters-refused-else-lands-mapped-data-and-key."""

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

CHECK = "aws-proxy-subtype-kinesis-putrecord-required-parameters-refused-else-lands-mapped-data-and-key"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "kinesis"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """CreateIntegration refuses a Kinesis-PutRecord subtype integration missing the required
    StreamName, Data and PartitionKey parameters, and the same subtype with all three mapped from
    the client's request body lands a record carrying exactly that data and partition key.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html
    """
    kinesis = ctx.client("kinesis")
    stream_name = _xname(ctx, "stream")
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

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-kinesis"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    # --- the required-parameter refusal: StreamName, Data and PartitionKey are all required.
    code, message = _error(
        lambda: agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationSubtype="Kinesis-PutRecord",
            PayloadFormatVersion="1.0",
            CredentialsArn=credentials_arn,
            RequestParameters={},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == (
        "Operation: Kinesis-PutRecord requires enabling passthrough, or defining all of the "
        "following parameters in the parameter mapping: [StreamName, Data, PartitionKey]"
    ), f"unexpected message {message!r}"

    # --- the positive control: all three mapped from the client's JSON body.
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationSubtype="Kinesis-PutRecord",
        PayloadFormatVersion="1.0",
        CredentialsArn=credentials_arn,
        RequestParameters={
            "StreamName": stream_name,
            "Data": "$request.body.data",
            "PartitionKey": "$request.body.pk",
        },
    )["IntegrationId"]
    # The route writes to the stream, so only a SigV4-signed caller of this account reaches it.
    agw.create_route(
        ApiId=api_id,
        RouteKey="POST /put",
        Target=f"integrations/{integration_id}",
        AuthorizationType="AWS_IAM",
    )
    agw.create_stage(
        ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=_xsvc_resource_tags()
    )
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )

    stored = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert stored.get("RequestParameters", {}).get("PartitionKey") == "$request.body.pk", (
        f"the PartitionKey mapping must be stored as authored, got "
        f"{stored.get('RequestParameters', {}).get('PartitionKey')!r}"
    )

    data_marker = ctx.unique_name("sim2real-xsvc-kindata-")
    partition_key = ctx.unique_name("sim2real-xsvc-kinpk-")
    url = f"{ctx.stage_url(api_endpoint, '$default')}/put"
    body = json.dumps({"data": data_marker, "pk": partition_key}).encode()
    status, _, text = _poll_http(
        ctx,
        url,
        method="POST",
        body=body,
        headers={"Content-Type": "application/json"},
        accept=lambda s: s == 200,
        description="POST /put reaching the Kinesis-PutRecord integration",
    )
    assert status == 200, f"expected 200 from the Kinesis-PutRecord subtype, got {status}: {text[:300]!r}"
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


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _list_shards(kinesis, stream_name):
    """Shard ids, or None while the stream briefly refuses ListShards right after reaching
    ACTIVE on DescribeStreamSummary (ResourceInUseException/CREATING)."""
    try:
        return [s["ShardId"] for s in kinesis.list_shards(StreamName=stream_name)["Shards"]]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceInUseException":
            return None
        raise


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _read_record_at(ctx, kinesis, stream_name, shard_ids, sequence_number, *, timeout_s):
    """The record at exactly ``sequence_number`` on whichever of ``shard_ids`` encodes it.

    ON_DEMAND streams may start with several shards; a sequence number is only valid on the one
    shard whose hash-key range produced it, so an ``InvalidArgumentException`` naming a different
    shard is expected on every other one, not a failure."""
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


def _signed_http(ctx, method, url, body=None, headers=None, timeout_s=20):
    """(status, headers, text) of one SigV4-signed request; status None on a transport error."""
    creds = ctx.client("sts")._request_signer._credentials.get_frozen_credentials()
    req = AWSRequest(method=method, url=url, data=body, headers=headers or {})
    SigV4Auth(creds, "execute-api", ctx.region).add_auth(req)
    raw = urllib.request.Request(url, data=body, method=method, headers=dict(req.headers))
    try:
        with urllib.request.urlopen(
            raw, timeout=timeout_s, context=_ssl_context(ctx.http_verify)
        ) as resp:
            return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read().decode("utf-8", "replace")
    except OSError as exc:
        return None, {}, f"connection error: {exc}"


def _poll_http(ctx, url, *, accept, method="GET", body=None, headers=None, timeout_s=90.0,
               interval_s=3.0, description="invoke URL"):
    """Signed requests to ``url`` until ``accept(status)``; TimeoutError with the last answer."""
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    while True:
        last = _signed_http(ctx, method, url, body=body, headers=headers)
        if accept(last[0]):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise TimeoutError(
        f"{description} ({url}) never reached an accepted status within {budget:.0f}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = None
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
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
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
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
