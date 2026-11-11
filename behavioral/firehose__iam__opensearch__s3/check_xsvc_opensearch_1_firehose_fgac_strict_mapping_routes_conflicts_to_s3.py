"""xsvc-opensearch-1-firehose-fgac-strict-mapping-routes-conflicts-to-s3."""
from __future__ import annotations

import base64
import datetime
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

CHECK = "xsvc-opensearch-1-firehose-fgac-strict-mapping-routes-conflicts-to-s3"
GROUP = "delivery"
SERVICES = ["firehose", "iam", "opensearch", "s3"]

# The prefix Firehose writes failed OpenSearch documents under when S3BackupMode is
# FailedDocumentsOnly and the backup S3Configuration declares no Prefix of its own.
FAILED_PREFIX = "AmazonOpenSearchService-failed/"
# The failed record's errorCode varies between runs (e.g. OS.AmazonOpenSearchServiceParseException
# or OS.ServiceException); only one code per batch in the "OS." namespace is stable.
ERROR_NAMESPACE = "OS."

ENGINE_VERSION = "OpenSearch_2.11"
MIN_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1,
                      "DedicatedMasterEnabled": False, "ZoneAwarenessEnabled": False}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
_SCENARIO = "xsvc-opensearch-1-firehose-strict"


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
    """Send an OpenSearch REST request over a TLS socket this function opens itself, with no SDK."""
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

    Paths carry no reserved characters, so the signed canonical URI equals the sent request line.
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
                time.sleep(2.0)
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


def _create_iam_master_domain(ctx, account, master_arn):
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
                                 "MasterUserOptions": {"MasterUserARN": master_arn}},
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
    budget = _capped(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"], last["ARN"]
        time.sleep(2.0)
    raise AssertionError(f"domain {name} published no endpoint within {budget}s "
                         f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})")


def _wait_master(ctx, host, creds, timeout_s=420.0):
    """Processing=False does not mean the security plugin accepts the IAM admin user yet."""
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _signed(ctx, host, creds, "GET", "/_cluster/health")
        if status == 200:
            return
        time.sleep(2.0)
    raise AssertionError(f"the IAM master never got 200 on /_cluster/health within {timeout_s}s "
                         f"(last HTTP {status!r}: {body!r})")


def _make_bucket(ctx, name):
    s3 = ctx.client("s3")
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


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("concern:data-plane", "concern:e2e", "dp:native", "plane:data", "axis:happy-path", "cap:c7", "timing:real-time")
def run(ctx) -> None:
    """Firehose into an FGAC OpenSearch domain indexes the 5 documents that fit a strict mapping into
    one date-suffixed index and backs the 2 conflicting ones up to S3 under the failed prefix, each
    with an "OS." errorCode, the index name and the original record.
    """
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    root_trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole"}]}
    started = datetime.datetime.now(datetime.timezone.utc).date()

    master_name = ctx.unique_name("sim2real-xsvc-osm-")
    # Domain ARN is not known yet; the admin role's ESHttp grant is scoped to sim2real-x1-* domains.
    master_arn = _make_role(ctx, master_name, root_trust, {
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "es:ESHttp*",
            "Resource": f"arn:aws:es:{ctx.region}:{account}:domain/sim2real-x1-*/*"}]})
    domain = _create_iam_master_domain(ctx, account, master_arn)

    # Provision the rest while the domain comes up.
    bucket = ctx.unique_name("sim2real-xsvc-fhos-")
    _make_bucket(ctx, bucket)
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{domain}"
    fh_role_arn = _firehose_role(ctx, ctx.unique_name("sim2real-xsvc-fhr-"), bucket, domain_arn)

    host, described_arn = _wait_domain(ctx, domain)
    assert described_arn == domain_arn, f"DescribeDomain ARN {described_arn!r} != {domain_arn!r}"

    # The stream activates while the security plugin comes up and the template and FGAC mapping
    # are written; no record is put before both exist.
    index = "sim2real-fh-strict"
    stream = ctx.unique_name("sim2real-xsvc-fhos-")
    _start_stream(ctx, stream, fh_role_arn, domain_arn, index, bucket)
    master = _assume(ctx, master_arn, "sim2real-master")
    _wait_master(ctx, host, master)

    # Strict mapping with qty coerce=False rejects the string "12" a default mapping would accept;
    # label is a keyword, so an object there cannot parse.
    status, body = _signed(ctx, host, master, "PUT", "/_index_template/sim2real-fh-strict", {
        "index_patterns": [f"{index}-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {"dynamic": "strict", "properties": {
                "seq": {"type": "integer"},
                "label": {"type": "keyword"},
                "qty": {"type": "integer", "coerce": False}}}}})
    assert status == 200, f"strict index template PUT returned HTTP {status!r}: {body!r}"

    status, body = _signed(ctx, host, master, "PUT",
                           "/_plugins/_security/api/roles/sim2real_fh_writer", {
                               "cluster_permissions": ["cluster_composite_ops", "cluster_monitor"],
                               "index_permissions": [{"index_patterns": [f"{index}*"],
                                                      "allowed_actions": ["crud", "create_index",
                                                                          "manage"]}]})
    assert status in (200, 201), f"FGAC role PUT returned HTTP {status!r}: {body!r}"
    status, body = _signed(ctx, host, master, "PUT",
                           "/_plugins/_security/api/rolesmapping/sim2real_fh_writer",
                           {"backend_roles": [fh_role_arn]})
    assert status in (200, 201), f"FGAC role mapping PUT returned HTTP {status!r}: {body!r}"

    _wait_stream_active(ctx, stream)

    valid = [{"seq": i, "label": f"ok-{i}", "qty": 10 * i} for i in range(5)]
    conflicting = [{"seq": 100, "label": "bad-coerce", "qty": "12"},
                   {"seq": 101, "label": {"not": "a-keyword"}, "qty": 1}]
    _put_batch(ctx, stream, valid + conflicting)

    deadline = time.monotonic() + _capped(ctx, 900.0)
    indices, count, keys, failed = [], None, [], []
    while time.monotonic() < deadline:
        indices = _indices_with_prefix(ctx, host, master, f"{index}-")
        count = _count(ctx, host, master, indices[0]) if len(indices) == 1 else None
        keys, failed = _failed_records(ctx, bucket)
        if (count or 0) >= 5 and len(failed) >= 2:
            break
        time.sleep(2.0)
    print(f"OBSERVED indices={indices!r} count={count!r} keys={keys!r}")
    for rec in failed:
        print("OBSERVED failed record:", {k: v for k, v in rec.items() if k != "rawData"})

    ended = datetime.datetime.now(datetime.timezone.utc).date()
    assert len(indices) == 1, (
        f"expected exactly one {index}-* index created by Firehose, found {indices!r}")
    m = re.fullmatch(rf"{re.escape(index)}-(\d{{4}})-(\d{{2}})-(\d{{2}})", indices[0])
    assert m, f"OneDay rotation index {indices[0]!r} is not {index}-YYYY-MM-DD"
    suffix = datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    assert started <= suffix <= ended, (
        f"index date suffix {suffix} is outside the run's UTC dates {started}..{ended}")
    assert count == 5, f"signed _count on {indices[0]!r} is {count!r}, expected exactly 5"

    status, body = _signed(ctx, host, master, "POST", f"/{indices[0]}/_search",
                           {"size": 20, "query": {"match_all": {}}})
    assert status == 200, f"_search returned HTTP {status!r}: {body!r}"
    seqs = sorted(h["_source"]["seq"] for h in body["hits"]["hits"])
    assert seqs == [0, 1, 2, 3, 4], f"indexed documents carry seq {seqs!r}, expected [0..4]"
    status, body = _signed(ctx, host, master, "GET", f"/{indices[0]}/_mapping")
    assert status == 200, f"_mapping returned HTTP {status!r}: {body!r}"
    mapping = body[indices[0]]["mappings"]
    assert mapping.get("dynamic") == "strict", (
        f"the Firehose-created index did not inherit the strict template: {mapping!r}")
    assert sorted(mapping["properties"]) == ["label", "qty", "seq"], (
        f"the strict index grew fields: {sorted(mapping['properties'])!r}")

    assert keys and all(k.startswith(FAILED_PREFIX) for k in keys), (
        f"backup objects are not all under {FAILED_PREFIX!r}: {keys!r}")
    assert len(failed) == 2, f"expected exactly 2 failed records in S3, got {len(failed)}"
    decoded = sorted((json.loads(base64.b64decode(r["rawData"])) for r in failed),
                     key=lambda d: d["seq"])
    assert decoded == conflicting, (
        f"rawData of the failed records decodes to {decoded!r}, expected {conflicting!r}")
    codes = sorted({str(r.get("errorCode")) for r in failed})
    assert len(codes) == 1 and codes[0].startswith(ERROR_NAMESPACE), (
        f"failed records carry errorCodes {codes!r}, expected one {ERROR_NAMESPACE}* code")
    for rec in failed:
        assert rec.get("osIndexName") == indices[0], (
            f"failed record names index {rec.get('osIndexName')!r}, expected {indices[0]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
