"""xsvc-opensearch-1-firehose-unmapped-role-denied-all-records-to-s3."""
from __future__ import annotations

import base64
import json
import random
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-opensearch-1-firehose-unmapped-role-denied-all-records-to-s3"
GROUP = "permission-chain"
SERVICES = ["firehose", "iam", "opensearch", "s3"]

FAILED_PREFIX = "AmazonOpenSearchService-failed/"
# The failed record's errorCode is not stable for this denial (OS.BulkWritePermissionDenied or
# OS.ServiceException); only one code per batch, in Firehose's "OS." namespace, holds.
ERROR_NAMESPACE = "OS."

ENGINE_VERSION = "OpenSearch_2.11"
MIN_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1,
                      "DedicatedMasterEnabled": False, "ZoneAwarenessEnabled": False}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
_SCENARIO = "xsvc-opensearch-1-firehose-unmapped"


def _capped(ctx, budget_s):
    """The wait bound, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, left)


def _read_to_eof(sock):
    parts = []
    while True:
        block = sock.recv(65536)
        if not block:
            return b"".join(parts)
        parts.append(block)


def _dechunk(body):
    out = bytearray()
    pos = 0
    while True:
        nl = body.find(b"\r\n", pos)
        if nl < 0:
            raise AssertionError(f"{DATAPLANE_MARKER}: chunked response truncated at byte {pos}")
        size = int(body[pos:nl].split(b";")[0].strip(), 16)
        pos = nl + 2
        if size == 0:
            return bytes(out)
        out += body[pos:pos + size]
        pos += size + 2


def _tls(ctx):
    """The TLS context for the target: the system trust store, the target's CA bundle, or none."""
    verify = ctx.http_verify
    if verify is False:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _native_request(ctx, host, method, path, *, headers, body=None, timeout=120):
    """Speak the OpenSearch REST protocol on a TLS socket this function opens itself.

    `dp:native`: the OpenSearch HTTP API is not an AWS Smithy API and nothing between this function
    and the cluster is an AWS SDK -- request line, headers, framing and chunked decoding are ours.
    """
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    for name, value in headers.items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    wire = ("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b"")
    url, _ = ctx.endpoint_route(host)
    target = urlsplit(url)
    secure = target.scheme == "https"
    try:
        raw = socket.create_connection(
            (target.hostname, target.port or (443 if secure else 80)), timeout=timeout)
    except OSError as exc:  # the endpoint the target published refused a connect
        raise AssertionError(f"{DATAPLANE_MARKER}: could not open a TLS socket to {host!r}: "
                             f"{type(exc).__name__}: {exc}") from exc
    try:
        sock = _tls(ctx).wrap_socket(raw, server_hostname=target.hostname) if secure else raw
        sock.settimeout(timeout)
        sock.sendall(wire)
        blob = _read_to_eof(sock)
    except OSError as exc:  # same classification, one layer in
        raise AssertionError(f"{DATAPLANE_MARKER}: {method} {path} to {host!r} did not complete: "
                             f"{type(exc).__name__}: {exc}") from exc
    finally:
        try:
            raw.close()
        except OSError:
            pass
    split = blob.find(b"\r\n\r\n")
    if split < 0:
        raise AssertionError(f"{DATAPLANE_MARKER}: no HTTP header terminator for {method} {path}: "
                             f"{blob[:200]!r}")
    head = blob[:split].decode("iso-8859-1")
    content = blob[split + 4:]
    fields = head.split("\r\n")[0].split(" ", 2)
    if len(fields) < 2 or not fields[1].isdigit():
        raise AssertionError(f"{DATAPLANE_MARKER}: unparseable status line {head[:80]!r}")
    seen = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            seen[k.strip().lower()] = v.strip()
    if seen.get("transfer-encoding", "").lower() == "chunked":
        content = _dechunk(content)
    text = content.decode("utf-8", errors="replace")
    try:
        return int(fields[1]), (json.loads(text) if text.strip() else {})
    except ValueError:
        return int(fields[1]), {"raw": text}


def _signed(ctx, host, creds, method, path, body=None):
    """SigV4-sign (service `es`) an OpenSearch REST call as `creds`, then send it ourselves.

    Paths here never carry a wildcard or a reserved character, so the canonical URI botocore signs
    is byte-identical to the request line we send.
    """
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = AWSRequest(method=method, url=f"https://{host}{path}", data=data or b"",
                     headers=headers)
    SigV4Auth(creds, "es", ctx.region).add_auth(req)
    return _native_request(ctx, host, method, path, headers=dict(req.headers.items()), body=data)


def _retry_access_denied(fn, *, what, timeout_s=120.0):
    """IAM propagation exposes no condition to poll; the bounded retry at first use IS the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "AccessDenied" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise AssertionError(f"{what} failed with {code!r}: "
                                 f"{exc.response.get('Error', {}).get('Message')!r}") from exc


def _make_role(ctx, name, trust, policy):
    iam = ctx.client("iam")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Description="sim2real xsvc-opensearch-1",
                          Tags=[{"Key": "sim2real", "Value": _SCENARIO}])["Role"]["Arn"]

    def _drop():
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)
    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return arn


def _assume(ctx, role_arn, session):
    out = _retry_access_denied(
        lambda: ctx.client("sts").assume_role(RoleArn=role_arn, RoleSessionName=session,
                                              DurationSeconds=3600),
        what=f"AssumeRole {role_arn}")["Credentials"]
    return Credentials(out["AccessKeyId"], out["SecretAccessKey"], out["SessionToken"])


def _delete_domain_quietly(osc, name):
    try:
        osc.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_iam_admin_domain(ctx, account, admin_arn):
    """Cheapest legal FGAC domain whose admin user is an IAM ROLE ARN (no internal user DB).

    The resource policy delegates to IAM (principal = this account's root), so every principal
    still needs an identity policy allowing es:ESHttp*, and FGAC then decides on top of that.
    """
    osc = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-x1-")[:28]
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, name))
    kwargs = dict(
        DomainName=name, EngineVersion=ENGINE_VERSION, ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS), EncryptionAtRestOptions={"Enabled": True},
        NodeToNodeEncryptionOptions={"Enabled": True},
        DomainEndpointOptions={"EnforceHTTPS": True,
                               "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
        AdvancedSecurityOptions={"Enabled": True, "InternalUserDatabaseEnabled": False,
                                 "MasterUserOptions": {"MasterUserARN": admin_arn}},
        AccessPolicies=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account}:domain/{name}/*"}]}),
        TagList=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    for attempt in range(12):
        time.sleep(random.uniform(0, 10.0) if attempt == 0 else 6.0 * attempt)
        try:
            osc.create_domain(**kwargs)
            return name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_domain(ctx, name, timeout_s=1800.0):
    osc = ctx.client("opensearch")
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    last = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"], last["ARN"]
        time.sleep(2.0)
    raise AssertionError(f"domain {name} published no endpoint within {timeout_s}s "
                         f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})")


def _wait_admin(ctx, host, creds, timeout_s=420.0):
    """Processing=False does not mean the security plugin accepts the IAM admin role yet."""
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _signed(ctx, host, creds, "GET", "/_cluster/health")
        if status == 200:
            return
        time.sleep(2.0)
    raise AssertionError(f"the IAM admin role never got 200 on /_cluster/health within {timeout_s}s "
                         f"(last HTTP {status!r}: {body!r})")


def _make_bucket(ctx, name):
    s3 = ctx.client("s3")
    # us-east-1 is the one region whose CreateBucket refuses an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _drop():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    ctx.on_cleanup(_drop)


def _firehose_role(ctx, name, bucket, domain_arn):
    return _make_role(
        ctx, name,
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole"}]},
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow",
             "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                        "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
             "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
            {"Effect": "Allow",
             "Action": ["es:DescribeDomain", "es:DescribeDomains", "es:DescribeDomainConfig",
                        "es:ESHttpPost", "es:ESHttpPut", "es:ESHttpGet"],
             "Resource": [domain_arn, f"{domain_arn}/*"]}]})


def _start_stream(ctx, name, role_arn, domain_arn, index, bucket):
    """DirectPut -> OpenSearch, OneDay rotation, failed documents only to S3, no retries."""
    fh = ctx.client("firehose")
    cfg = {
        "RoleARN": role_arn, "DomainARN": domain_arn, "IndexName": index,
        "IndexRotationPeriod": "OneDay",
        "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
        "RetryOptions": {"DurationInSeconds": 0},
        "S3BackupMode": "FailedDocumentsOnly",
        "S3Configuration": {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}",
                            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                            "CompressionFormat": "UNCOMPRESSED"},
        "CloudWatchLoggingOptions": {"Enabled": False},
    }
    deadline = time.monotonic() + _capped(ctx, 180.0)
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name, DeliveryStreamType="DirectPut",
                AmazonopensearchserviceDestinationConfiguration=cfg,
                Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
            break
        except ClientError as exc:
            # The role was created seconds ago: Firehose refuses a role it cannot yet assume with
            # InvalidArgumentException, and that is IAM propagation, not the contract under test.
            if (exc.response.get("Error", {}).get("Code") != "InvalidArgumentException"
                    or time.monotonic() >= deadline):
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _delete_stream(fh, name))


# Teardown has 1800 s in all: the two stream deletes run first under this deadline each, with a
# margin for the role, bucket and domain deletes after them.
_DELETE_STREAM_DEADLINE_S = 600


def _delete_stream(fh, name):
    """Teardown: retry ResourceInUseException, then poll DescribeDeliveryStream every 2 s until it
    answers ResourceNotFoundException, as the delete is asynchronous. One deadline bounds both."""
    deadline = time.monotonic() + _DELETE_STREAM_DEADLINE_S
    while True:
        try:
            fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)
    while True:
        try:
            desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"stream {name} still {desc.get('DeliveryStreamStatus')!r} at the "
                               f"teardown deadline")
        time.sleep(2.0)


def _wait_stream_active(ctx, name):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + _capped(ctx, 600.0)
    desc = {}
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return
        if desc["DeliveryStreamStatus"] == "CREATING_FAILED":
            raise AssertionError(f"stream {name} CREATING_FAILED: "
                                 f"{desc.get('FailureDescription')!r}")
        time.sleep(2.0)
    raise AssertionError(f"stream {name} not ACTIVE within 600s: "
                         f"{desc.get('DeliveryStreamStatus')!r}")


def _put_batch(ctx, stream, docs):
    out = ctx.client("firehose").put_record_batch(
        DeliveryStreamName=stream,
        Records=[{"Data": json.dumps(d, sort_keys=True).encode()} for d in docs])
    assert out["FailedPutCount"] == 0, f"PutRecordBatch rejected records at ingest: {out!r}"


def _failed_records(ctx, bucket):
    """Every JSON record Firehose wrote to the backup bucket, with the key it came from."""
    s3 = ctx.client("s3")
    keys, records = [], []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
            text = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode()
            dec, pos = json.JSONDecoder(), 0
            while True:
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                if pos >= len(text):
                    break
                rec, pos = dec.raw_decode(text, pos)
                records.append(rec)
    return keys, records


def _indices_with_prefix(ctx, host, creds, prefix):
    status, body = _signed(ctx, host, creds, "GET", "/_cat/indices?format=json")
    assert status == 200, f"_cat/indices returned HTTP {status!r}: {body!r}"
    return sorted(row["index"] for row in body if row["index"].startswith(prefix))


def _count(ctx, host, creds, index):
    status, body = _signed(ctx, host, creds, "POST", f"/{index}/_refresh")
    assert status == 200, f"_refresh of {index!r} returned HTTP {status!r}: {body!r}"
    status, body = _signed(ctx, host, creds, "GET", f"/{index}/_count")
    assert status == 200, f"signed _count on {index!r} returned HTTP {status!r}: {body!r}"
    return body.get("count")


def _wait_delivery(ctx, host, creds, *, ctl_index, ctl_bucket, unm_bucket, want, timeout_s=900.0):
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    state = {}
    while time.monotonic() < deadline:
        ctl = _indices_with_prefix(ctx, host, creds, f"{ctl_index}-")
        state["ctl_indices"] = ctl
        state["ctl_count"] = _count(ctx, host, creds, ctl[0]) if len(ctl) == 1 else None
        state["unm_keys"], state["unm_failed"] = _failed_records(ctx, unm_bucket)
        if (state["ctl_count"] or 0) >= want and len(state["unm_failed"]) >= want:
            break
        time.sleep(2.0)
    state["ctl_keys"], state["ctl_failed"] = _failed_records(ctx, ctl_bucket)
    return state


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c7",
    "timing:real-time",
)
def run(ctx) -> None:
    """A Firehose role allowed es:ESHttp* by IAM but unmapped in FGAC indexes nothing; every record
    lands in the S3 failed prefix intact, while a mapped control stream on the same domain indexes
    the batch. Mapping the role afterwards makes the same stream deliver.
    """
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    root_trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole"}]}

    admin_arn = _make_role(ctx, ctx.unique_name("sim2real-xsvc-osm-"), root_trust, {
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "es:ESHttp*",
            "Resource": f"arn:aws:es:{ctx.region}:{account}:domain/sim2real-x1-*/*"}]})
    domain = _create_iam_admin_domain(ctx, account, admin_arn)
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{domain}"

    ctl_bucket = ctx.unique_name("sim2real-xsvc-fhc-")
    unm_bucket = ctx.unique_name("sim2real-xsvc-fhu-")
    _make_bucket(ctx, ctl_bucket)
    _make_bucket(ctx, unm_bucket)
    ctl_role = _firehose_role(ctx, ctx.unique_name("sim2real-xsvc-fhrc-"), ctl_bucket, domain_arn)
    # Identical IAM grant to the control's: the ONLY difference between the two streams is the
    # FGAC role mapping below.
    unm_role = _firehose_role(ctx, ctx.unique_name("sim2real-xsvc-fhru-"), unm_bucket, domain_arn)

    host, _ = _wait_domain(ctx, domain)

    # Both streams activate while the security plugin comes up and the FGAC mapping is written;
    # no record is put before the mapping exists.
    ctl_index, unm_index = "sim2real-fh-ctl", "sim2real-fh-unm"
    ctl_stream = ctx.unique_name("sim2real-xsvc-fhc-")
    unm_stream = ctx.unique_name("sim2real-xsvc-fhu-")
    _start_stream(ctx, ctl_stream, ctl_role, domain_arn, ctl_index, ctl_bucket)
    _start_stream(ctx, unm_stream, unm_role, domain_arn, unm_index, unm_bucket)

    admin = _assume(ctx, admin_arn, "sim2real-admin")
    _wait_admin(ctx, host, admin)

    status, body = _signed(ctx, host, admin, "PUT",
                           "/_plugins/_security/api/roles/sim2real_fh_writer", {
                               "cluster_permissions": ["cluster_composite_ops", "cluster_monitor"],
                               "index_permissions": [{"index_patterns": ["sim2real-fh-*"],
                                                      "allowed_actions": ["crud", "create_index",
                                                                          "manage"]}]})
    assert status in (200, 201), f"FGAC role PUT returned HTTP {status!r}: {body!r}"
    mapping_path = "/_plugins/_security/api/rolesmapping/sim2real_fh_writer"
    status, body = _signed(ctx, host, admin, "PUT", mapping_path,
                           {"backend_roles": [ctl_role]})
    assert status in (200, 201), f"FGAC role mapping PUT returned HTTP {status!r}: {body!r}"

    _wait_stream_active(ctx, ctl_stream)
    _wait_stream_active(ctx, unm_stream)

    batch = [{"seq": i, "label": f"doc-{i}", "qty": i} for i in range(5)]
    _put_batch(ctx, ctl_stream, batch)
    _put_batch(ctx, unm_stream, batch)

    state = _wait_delivery(ctx, host, admin, ctl_index=ctl_index, ctl_bucket=ctl_bucket,
                           unm_bucket=unm_bucket, want=len(batch))
    print("OBSERVED", {k: v for k, v in state.items() if not k.endswith("failed")})
    for rec in state["unm_failed"]:
        print("OBSERVED unmapped failed record:", {k: v for k, v in rec.items() if k != "rawData"})

    # The mapped control stream is the barrier, not a sleep: it proves the batch was processed.
    assert len(state["ctl_indices"]) == 1, (
        f"control stream created indices {state['ctl_indices']!r}, expected exactly one")
    assert state["ctl_count"] == 5, (
        f"control stream's index holds {state['ctl_count']!r} documents, expected 5")
    assert state["ctl_keys"] == [], (
        f"the mapped control stream backed up failures it should not have: {state['ctl_keys']!r}")

    # The effect is absent: nothing from the unmapped stream reached the domain.
    unm_indices = _indices_with_prefix(ctx, host, admin, unm_index)
    assert unm_indices == [], (
        f"the unmapped stream's role created/wrote indices {unm_indices!r} -- FGAC let it in")
    # ...and every record it accepted is in its failed prefix, byte-for-byte.
    keys, failed = state["unm_keys"], state["unm_failed"]
    assert keys and all(k.startswith(FAILED_PREFIX) for k in keys), (
        f"unmapped stream's backup objects are not all under {FAILED_PREFIX!r}: {keys!r}")
    assert len(failed) == 5, f"expected all 5 records in the failed prefix, got {len(failed)}"
    decoded = sorted((json.loads(base64.b64decode(r["rawData"])) for r in failed),
                     key=lambda d: d["seq"])
    assert decoded == batch, f"failed rawData decodes to {decoded!r}, expected {batch!r}"
    codes = sorted({str(r.get("errorCode")) for r in failed})
    assert len(codes) == 1 and codes[0].startswith(ERROR_NAMESPACE), (
        f"failed records carry errorCodes {codes!r}, expected one {ERROR_NAMESPACE}* code")
    names = sorted({r.get("osIndexName") for r in failed})
    assert len(names) == 1 and re.fullmatch(rf"{unm_index}-\d{{4}}-\d{{2}}-\d{{2}}", names[0]), (
        f"failed records name would-be index {names!r}, expected one {unm_index}-YYYY-MM-DD")

    # Repair the one broken thing and the same stream delivers.
    status, body = _signed(ctx, host, admin, "PUT", mapping_path,
                           {"backend_roles": [ctl_role, unm_role]})
    assert status == 200, f"re-mapping returned HTTP {status!r}: {body!r}"
    repaired = [{"seq": 10 + i, "label": f"fix-{i}", "qty": i} for i in range(5)]
    deadline = time.monotonic() + _capped(ctx, 900.0)
    unm_indices, unm_count, sent_at = [], None, time.monotonic()
    _put_batch(ctx, unm_stream, repaired)
    while time.monotonic() < deadline:
        unm_indices = _indices_with_prefix(ctx, host, admin, unm_index)
        unm_count = _count(ctx, host, admin, unm_indices[0]) if len(unm_indices) == 1 else None
        if (unm_count or 0) >= 5:
            break
        # A record still in flight when the mapping lands can fail once; re-send only the batch
        # (never assert on its count) if nothing arrived after a full buffering window.
        if unm_count is None and time.monotonic() - sent_at > 180.0:
            _put_batch(ctx, unm_stream, repaired)
            sent_at = time.monotonic()
        time.sleep(2.0)
    assert len(unm_indices) == 1 and (unm_count or 0) >= 5, (
        f"after mapping its role the stream still delivered nothing: indices={unm_indices!r} "
        f"count={unm_count!r}")
    status, body = _signed(ctx, host, admin, "POST", f"/{unm_indices[0]}/_search",
                           {"size": 50, "query": {"match_all": {}}})
    assert status == 200, f"_search returned HTTP {status!r}: {body!r}"
    seqs = sorted({h["_source"]["seq"] for h in body["hits"]["hits"]})
    assert seqs == [10, 11, 12, 13, 14], (
        f"the repaired stream indexed seq {seqs!r}, expected only the post-repair batch")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
