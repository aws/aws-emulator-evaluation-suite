"""instance-job-writes-objects-and-every-s3-event-lands-in-sqs-with-matching-etag-size-sequencer."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "instance-job-writes-objects-and-every-s3-event-lands-in-sqs-with-matching-etag-size-sequencer"
)
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

_VPC_CIDR = "10.72.0.0/16"
_PRIVATE_CIDR = "10.72.10.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = (
    "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
)
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyUpdates",
)
_N = 20
_SOURCE_BYTES = 1048576
_SOURCE_KEY = "in/source"
_OVERWRITE_BYTES = 4096


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A private instance's job writes 20 derived objects through an S3 gateway endpoint, and SQS
    receives one S3 event for exactly those keys carrying the eTag, size and sequencer of the bytes
    written; an overwrite and a delete raise the sequencer, and the `in/` queue receives nothing.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"iface": [], "gw": [], "subnets": [], "sgs": [], "queues": []}
    try:
        _build(ctx, ec2, s3, sqs, ssm, iam, st)
        _assert_events(s3, sqs, ssm, st)
    finally:
        _teardown(ec2, s3, sqs, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, s3, sqs, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-b1evt-")
    st["name"], st["region"], st["nonce"] = name, region, name
    st["account"] = ctx.client("sts").get_caller_identity()["Account"]

    zone = _usable_zone(ec2)
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    private_subnet = _create_subnet(
        ctx, ec2, st, _PRIVATE_CIDR, zone, name + "-private"
    )
    st["private_rt"] = _create_route_table(
        ctx, ec2, st, private_subnet, name + "-private-rt"
    )

    instance_sg = _create_sg(ctx, ec2, st, name + "-instance", "sim2real b1 job host")
    endpoint_sg = _create_sg(
        ctx, ec2, st, name + "-endpoint", "sim2real b1 interface endpoints"
    )
    ec2.authorize_security_group_ingress(
        GroupId=endpoint_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "UserIdGroupPairs": [{"GroupId": instance_sg}],
            }
        ],
    )

    for svc in ("ssm", "ssmmessages", "ec2messages"):
        ep = ec2.create_vpc_endpoint(
            VpcEndpointType="Interface",
            VpcId=vpc_id,
            ServiceName=f"com.amazonaws.{region}.{svc}",
            SubnetIds=[private_subnet],
            SecurityGroupIds=[endpoint_sg],
            PrivateDnsEnabled=True,
            TagSpecifications=[
                {"ResourceType": "vpc-endpoint", "Tags": _tags_for(name)}
            ],
        )["VpcEndpoint"]["VpcEndpointId"]
        st["iface"].append(ep)
        ctx.on_cleanup(_gone_ok(lambda ep=ep: ec2.delete_vpc_endpoints(VpcEndpointIds=[ep])))
    for ep in st["iface"]:
        _poll(
            lambda ep=ep: _endpoint_state(ec2, ep),
            lambda s: s == "available",
            timeout_s=420,
            interval_s=10,
            what=f"interface endpoint {ep} becoming available",
        )

    gw = ec2.create_vpc_endpoint(
        VpcEndpointType="Gateway",
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.s3",
        RouteTableIds=[st["private_rt"]],
        TagSpecifications=[
            {"ResourceType": "vpc-endpoint", "Tags": _tags_for(name + "-s3-gw")}
        ],
    )["VpcEndpoint"]["VpcEndpointId"]
    st["gw"].append(gw)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[gw])))

    bucket = name + "-bkt"
    st["bucket"] = bucket
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
    )
    ctx.on_cleanup(_gone_ok(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})

    out_q = _create_queue(ctx, sqs, st, name + "-out", bucket, st["account"])
    in_q = _create_queue(ctx, sqs, st, name + "-in", bucket, st["account"])
    st["out_q"], st["in_q"] = out_q, in_q
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "Id": "out-created",
                    "QueueArn": _queue_arn(sqs, out_q),
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "out/"}]}
                    },
                },
                {
                    "Id": "out-removed",
                    "QueueArn": _queue_arn(sqs, out_q),
                    "Events": ["s3:ObjectRemoved:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "out/"}]}
                    },
                },
                {
                    "Id": "in-created",
                    "QueueArn": _queue_arn(sqs, in_q),
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "in/"}]}
                    },
                },
            ]
        },
    )

    source = _source_bytes(st["nonce"])
    st["source"] = source
    s3.put_object(Bucket=bucket, Key=_SOURCE_KEY, Body=source)

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name, bucket)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    instance_id = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami,
            InstanceType=_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": private_subnet,
                    "Groups": [instance_sg],
                    "AssociatePublicIpAddress": False,
                }
            ],
            IamInstanceProfile={"Name": role_name},
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            TagSpecifications=[
                {"ResourceType": rt, "Tags": _tags_for(name)}
                for rt in ("instance", "volume")
            ],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=30,
        delay=5.0,
    )["Instances"][0]["InstanceId"]
    st["instance"] = instance_id
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(_gone_ok(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    info = _poll(
        lambda: _agent_view(ssm, instance_id),
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=600,
        interval_s=10,
        what=f"the SSM agent on private instance {instance_id} coming Online",
    )
    assert info["PingStatus"] == "Online", f"agent view was {info!r}"


# ===== the claim ============================================================
def _assert_events(s3, sqs, ssm, st) -> None:
    bucket, out_q, in_q = st["bucket"], st["out_q"], st["in_q"]
    expected = _expected_parts(st["source"])

    # The pre-condition that makes every later count meaningful: both queues empty. This also
    # absorbs S3's own `s3:TestEvent` and the `in/source` PUT the check itself made.
    _drain(sqs, out_q)
    _drain(sqs, in_q)
    assert _drain(sqs, out_q) == [] and _drain(sqs, in_q) == [], (
        "both queues must be empty before the job runs"
    )

    started = dt.datetime.now(dt.timezone.utc)
    inv = _run_phase(ssm, st["instance"], _job_script(st["region"], bucket))
    manifest = _json_line(inv)
    assert inv["ResponseCode"] == 0, (
        f"the job failed on the host: rc={inv['ResponseCode']!r} "
        f"stderr={inv['StandardErrorContent'][-600:]!r}"
    )
    assert manifest["_src_sha256"] == hashlib.sha256(st["source"]).hexdigest(), (
        f"the job must have read the input object through the gateway endpoint; it reported "
        f"{manifest['_src_sha256']!r} for {_SOURCE_KEY!r}"
    )
    assert sorted(k for k in manifest if not k.startswith("_")) == sorted(expected), (
        f"the job reported {sorted(k for k in manifest if not k.startswith('_'))!r}, the check "
        f"predicts {sorted(expected)!r}"
    )
    for key, want in expected.items():
        got = manifest[key]
        assert (got["size"], got["sha256"], got["md5"]) == (
            want["size"],
            want["sha256"],
            want["md5"],
        ), (
            f"the job's own manifest for {key!r} is {got!r}, the check predicts {want!r} from the "
            f"input bytes it PUT"
        )

    # --- the 20 notification records, de-duplicated by (key, sequencer) ------
    records = _collect(sqs, out_q, want_keys=set(expected), timeout_s=300, settle_s=45)
    by_key = {}
    for r in records:
        by_key.setdefault(r["s3"]["object"]["key"], []).append(r)
    assert sorted(by_key) == sorted(expected), (
        f"exactly the 20 keys the job wrote must produce a record -- no missing, no extra; the "
        f"queue delivered {sorted(by_key)!r}"
    )
    for key, rs in by_key.items():
        assert len(rs) == 1, (
            f"after de-duplicating by (key, sequencer) exactly one record may remain per key; "
            f"{key!r} has {rs!r}"
        )
    first = {k: v[0] for k, v in by_key.items()}

    principals = set()
    sequencers = {}
    for key, want in expected.items():
        r = first[key]
        obj = r["s3"]["object"]
        assert r["eventName"] == "ObjectCreated:Put", (
            f"{key!r} was written with a single PutObject, so its record must be "
            f"ObjectCreated:Put; it is {r['eventName']!r}"
        )
        assert obj["size"] == want["size"], (
            f"the record for {key!r} reports size {obj['size']!r}, the job wrote "
            f"{want['size']!r} bytes"
        )
        assert obj["eTag"] == want["md5"], (
            f"the record for {key!r} reports eTag {obj['eTag']!r}; the MD5 of the bytes the check "
            f"predicts is {want['md5']!r}"
        )
        head = s3.head_object(Bucket=bucket, Key=key)
        assert head["ETag"].strip('"') == want["md5"], (
            f"S3's own ETag for {key!r} is {head['ETag']!r}, predicted {want['md5']!r}"
        )
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert hashlib.sha256(body).hexdigest() == want["sha256"], (
            f"the stored bytes of {key!r} are not the derived content the job reported"
        )
        assert r["s3"]["bucket"]["name"] == bucket, r
        assert r["s3"]["bucket"]["arn"] == f"arn:aws:s3:::{bucket}", r
        assert r["awsRegion"] == st["region"], r
        assert r["eventSource"] == "aws:s3", r
        assert urllib.parse.unquote_plus(obj["key"]) == key, (
            f"the record's key {obj['key']!r} does not decode to {key!r}"
        )
        when = _parse_iso(r["eventTime"])
        assert started <= when <= dt.datetime.now(dt.timezone.utc), (
            f"the record for {key!r} is timestamped {r['eventTime']!r}, outside the window between "
            f"the job's start at {started.isoformat()!r} and now"
        )
        assert obj["sequencer"] and all(
            c in "0123456789ABCDEFabcdef" for c in obj["sequencer"]
        ), (
            f"the record for {key!r} carries sequencer {obj['sequencer']!r}, which must be a "
            f"non-empty hex string"
        )
        sequencers[key] = obj["sequencer"]
        principals.add(r["userIdentity"]["principalId"])
    assert len(set(sequencers.values())) == _N, (
        f"the {_N} records must carry {_N} distinct sequencers; they carry "
        f"{sorted(set(sequencers.values()))!r}"
    )
    assert len(principals) == 1, (
        f"one assumed-role session on one host did all {_N} writes, so every record must name the "
        f"same principal; the records name {sorted(principals)!r}"
    )

    # --- delivery absence: the `in/` queue must have received nothing --------
    leaked = _holds_for(
        lambda: _drain(sqs, in_q),
        lambda got: got == [],
        seconds=60,
        interval_s=10,
        what=f"the in/-prefixed queue staying empty while only out/ was written",
    )
    assert leaked == [], (
        f"the queue subscribed to in/ received {leaked!r} while the job wrote only under out/"
    )
    approx = sqs.get_queue_attributes(
        QueueUrl=in_q, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert approx == "0", (
        f"a second, independent observable on the in/ queue disagrees with the empty receive: "
        f"ApproximateNumberOfMessages={approx!r}"
    )

    listed = _list_keys(s3, bucket, prefix="out/")
    assert sorted(listed) == sorted(expected), (
        f"the bucket holds {sorted(listed)!r} under out/, the job wrote {sorted(expected)!r}"
    )

    # --- ordering arms: overwrite then delete out/part-00, from the same host
    key0 = "out/part-00"
    before_seq = sequencers[key0]
    before = expected[key0]
    overwrite = _derived(st["source"], b"overwrite", _OVERWRITE_BYTES)
    inv2 = _run_phase(ssm, st["instance"], _mutate_script(st["region"], bucket, key0))
    assert inv2["ResponseCode"] == 0, (
        f"the overwrite/delete phase failed on the host: rc={inv2['ResponseCode']!r} "
        f"stderr={inv2['StandardErrorContent'][-600:]!r}"
    )
    mutated = _json_line(inv2)
    assert mutated["sha256"] == hashlib.sha256(overwrite).hexdigest(), (
        f"the host reported overwriting {key0!r} with {mutated!r}, the check predicts "
        f"{hashlib.sha256(overwrite).hexdigest()!r}"
    )

    created2, removed = _collect_mutations(sqs, out_q, key0, timeout_s=300)
    assert created2["eventName"] == "ObjectCreated:Put", created2
    o2 = created2["s3"]["object"]
    assert o2["size"] == _OVERWRITE_BYTES and o2["size"] != before["size"], (
        f"the overwrite record reports size {o2['size']!r}; it must be {_OVERWRITE_BYTES} and "
        f"differ from the original {before['size']!r}"
    )
    assert (
        o2["eTag"] == hashlib.md5(overwrite).hexdigest() and o2["eTag"] != before["md5"]
    ), (
        f"the overwrite record reports eTag {o2['eTag']!r}, predicted "
        f"{hashlib.md5(overwrite).hexdigest()!r} and it must differ from {before['md5']!r}"
    )
    assert len(o2["sequencer"]) == len(before_seq), (
        f"S3 sequencers for one key must be comparable as fixed-width hex; got {o2['sequencer']!r} "
        f"and {before_seq!r}"
    )
    assert o2["sequencer"] > before_seq, (
        f"the overwrite's sequencer {o2['sequencer']!r} must sort strictly after the create's "
        f"{before_seq!r} -- this is the only documented way to order two writes to one key"
    )

    assert removed["eventName"] == "ObjectRemoved:Delete", (
        f"deleting {key0!r} must produce an ObjectRemoved:Delete record; it produced "
        f"{removed['eventName']!r}"
    )
    o3 = removed["s3"]["object"]
    assert o3["sequencer"] > o2["sequencer"], (
        f"the delete's sequencer {o3['sequencer']!r} must sort after the overwrite's "
        f"{o2['sequencer']!r}"
    )
    assert "size" not in o3 and "eTag" not in o3, (
        f"an ObjectRemoved record's object carries neither size nor eTag; this one is {o3!r}"
    )

    gone = _error_code(lambda: s3.head_object(Bucket=bucket, Key=key0))
    assert gone == "404", (
        f"{key0!r} must be absent after the host deleted it; HeadObject returned {gone!r}"
    )
    remaining = _list_keys(s3, bucket, prefix="out/")
    assert sorted(remaining) == sorted(k for k in expected if k != key0), (
        f"the bucket holds {sorted(remaining)!r} under out/ after the delete"
    )


# ===== in-band teardown =====================================================
def _teardown(ec2, s3, sqs, iam, st) -> list:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises naming each one that failed on anything but an already-gone code."""
    left = []

    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    if st.get("instance"):
        _step("instance", lambda: _terminate_and_wait(ec2, st["instance"]))
    endpoints = list(st.get("iface", [])) + list(st.get("gw", []))
    if endpoints:
        _step("endpoints", lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=endpoints))
        _step(
            "endpoints-deleted",
            lambda: _poll(
                lambda: [
                    e
                    for e in endpoints
                    if _endpoint_state(ec2, e) not in ("deleted", "gone")
                ],
                lambda pending: pending == [],
                timeout_s=300,
                interval_s=10,
                what="the VPC endpoints reporting deleted",
            ),
        )
    if st.get("vpc"):
        _step(
            "eni-drain",
            lambda: _poll(
                lambda: _vpc_enis(ec2, st["vpc"]),
                lambda enis: enis == [],
                timeout_s=420,
                interval_s=10,
                what=f"every ENI in {st['vpc']!r} draining",
            ),
        )
    if st.get("bucket"):
        _step("bucket", lambda: _empty_and_delete_bucket(s3, st["bucket"]))
    for q in st.get("queues", []):
        _step(f"queue {q}", lambda u=q: sqs.delete_queue(QueueUrl=u))
    if st.get("profile"):
        _step(
            "instance-profile",
            lambda: _drop_instance_profile(iam, st["profile"], st["role"]),
        )
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    # REVERSED deliberately: the endpoint group's ingress rule names the instance group in
    # `UserIdGroupPairs`, and a security group referenced by another group's rule cannot be
    # deleted (DependencyViolation), which would strand the VPC.
    for sg in reversed(st.get("sgs", [])):
        _step(
            f"sg {sg}",
            lambda s=sg: _retry_dependency(
                lambda: ec2.delete_security_group(GroupId=s)
            ),
        )
    for rt_id, assoc in st.get("rt", []):
        _step(
            f"rt-assoc {assoc}",
            lambda a=assoc: ec2.disassociate_route_table(AssociationId=a),
        )
        _step(
            f"rt {rt_id}",
            lambda r=rt_id: _retry_dependency(
                lambda: ec2.delete_route_table(RouteTableId=r)
            ),
        )
    for subnet in st.get("subnets", []):
        _step(
            f"subnet {subnet}",
            lambda s=subnet: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=s)),
        )
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
    if st.get("vpc"):
        _step("vpc-gone", lambda: _assert_vpc_gone(ec2, st["vpc"]))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 - collected, raised below
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")
    return left


# ===== helpers ===============================================================


def _assert_vpc_gone(ec2, vpc) -> None:
    """Verified absence, not a delete that returned 200: raise while DescribeVpcs still lists it."""
    still = ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"]
    if still:
        raise AssertionError(f"vpc {vpc} is still describable: {still!r}")
_GONE_CODES = (
    "NoSuchEntity",
    "NoSuchBucket",
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidInstanceID.NotFound",
    "InvalidVpcEndpointId.NotFound",
    "InvalidAssociationID.NotFound",
    "AWS.SimpleQueueService.NonExistentQueue",
)


def _gone_ok(fn):
    """A cleanup step that tolerates the resource being gone already: the ordered teardown in the
    `finally` deletes the same resources first, so this second net finds most of them absent."""

    def step():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise

    return step


def _tags_for(name):
    return [
        {"Key": "Name", "Value": name},
        {"Key": "sim2real", "Value": "b1-s3-events-in-sqs"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _source_bytes(nonce):
    buf = b""
    i = 0
    while len(buf) < _SOURCE_BYTES:
        buf += hashlib.sha256((nonce + ":" + str(i)).encode()).digest()
        i += 1
    return buf[:_SOURCE_BYTES]


def _derived(source, salt, nbytes):
    """The body the job must produce. The guest runs a byte-identical algorithm."""
    digest = hashlib.sha256(source + salt).digest()
    return (digest * (nbytes // len(digest) + 1))[:nbytes]


def _expected_parts(source):
    out = {}
    for i in range(_N):
        nbytes = 1024 * (i + 1)
        body = _derived(source, str(i).encode(), nbytes)
        out["out/part-%02d" % i] = {
            "size": nbytes,
            "sha256": hashlib.sha256(body).hexdigest(),
            "md5": hashlib.md5(body).hexdigest(),
        }
    return out


def _parse_iso(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _error_code(fn):
    """The ClientError code raised by fn. An unexpected SUCCESS raises, so it can never be
    confused with a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be refused but it succeeded")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _holds_for(probe, predicate, seconds, interval_s=10.0, what=""):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if not predicate(last):
            raise AssertionError(f"{what or 'condition'} stopped holding: {last!r}")
        time.sleep(interval_s)
    return last


def _retry_dependency(fn, timeout_s=240, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") == "DependencyViolation"
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _usable_zone(ec2):
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offerings were "
        f"{sorted(offered)!r}"
    )
    return usable[0]


def _create_subnet(ctx, ec2, st, cidr, zone, tag_name):
    subnet_id = ec2.create_subnet(
        VpcId=st["vpc"],
        CidrBlock=cidr,
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _create_route_table(ctx, ec2, st, subnet_id, tag_name):
    rt_id = ec2.create_route_table(
        VpcId=st["vpc"],
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": _tags_for(tag_name)}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)[
        "AssociationId"
    ]
    st.setdefault("rt", []).append((rt_id, assoc))
    ctx.on_cleanup(_gone_ok(lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    return rt_id


def _create_sg(ctx, ec2, st, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name,
        Description=description,
        VpcId=st["vpc"],
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": _tags_for(group_name)}
        ],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_security_group(GroupId=sg)))
    return sg


def _endpoint_state(ec2, endpoint_id):
    try:
        eps = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidVpcEndpointId.NotFound":
            return "gone"
        raise
    return eps[0]["State"] if eps else "gone"


def _vpc_enis(ec2, vpc_id):
    return [
        e["NetworkInterfaceId"]
        for e in ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["NetworkInterfaces"]
    ]


def _create_queue(ctx, sqs, st, queue_name, bucket, account):
    url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real": "b1-s3-events-in-sqs"}
    )["QueueUrl"]
    st["queues"].append(url)
    ctx.on_cleanup(_gone_ok(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = _queue_arn(sqs, url)
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {
                                "ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"},
                                "StringEquals": {"aws:SourceAccount": account},
                            },
                        }
                    ],
                }
            )
        },
    )
    return url


def _queue_arn(sqs, url):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]


def _drain(sqs, url, wait_s=1):
    """Receive and DELETE everything currently visible, returning the parsed bodies."""
    out = []
    while True:
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait_s,
            VisibilityTimeout=30,
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _records(bodies):
    """S3 notification bodies carry a `Records` list; S3's own `s3:TestEvent` does not."""
    out = []
    for body in bodies:
        for r in body.get("Records", []):
            out.append(r)
    return out


def _collect(sqs, url, want_keys, timeout_s, settle_s):
    """Collect until every wanted key is seen, then keep collecting for `settle_s` so a 21st
    record can be detected. De-duplicated by (key, sequencer): S3 delivery is at-least-once."""
    seen = {}
    deadline = time.monotonic() + timeout_s
    while True:
        for r in _records(_drain(sqs, url, wait_s=5)):
            seen[(r["s3"]["object"]["key"], r["s3"]["object"].get("sequencer"))] = r
        if want_keys <= {k for k, _ in seen}:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"only {sorted({k for k, _ in seen})!r} of {sorted(want_keys)!r} arrived within "
                f"{timeout_s}s"
            )
    settle_deadline = time.monotonic() + settle_s
    while time.monotonic() < settle_deadline:
        for r in _records(_drain(sqs, url, wait_s=5)):
            seen[(r["s3"]["object"]["key"], r["s3"]["object"].get("sequencer"))] = r
    return list(seen.values())


def _collect_mutations(sqs, url, key, timeout_s):
    """The overwrite's ObjectCreated and the delete's ObjectRemoved record for one key."""
    created, removed = {}, {}
    deadline = time.monotonic() + timeout_s
    while True:
        for r in _records(_drain(sqs, url, wait_s=5)):
            if r["s3"]["object"]["key"] != key:
                # A late at-least-once redelivery of one of the 20 create records; the "no extras"
                # property was already settled in _collect, so it is not a finding here.
                continue
            target = created if r["eventName"].startswith("ObjectCreated") else removed
            target[r["s3"]["object"]["sequencer"]] = r
        if created and removed:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the overwrite and delete records for {key!r} did not both arrive within "
                f"{timeout_s}s (created={sorted(created)!r} removed={sorted(removed)!r})"
            )
    assert len(created) == 1 and len(removed) == 1, (
        f"exactly one overwrite and one delete record may remain after de-duplicating by "
        f"sequencer; got created={created!r} removed={removed!r}"
    )
    return next(iter(created.values())), next(iter(removed.values()))


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        victims = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if victims:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
    s3.delete_bucket(Bucket=bucket)


def _list_keys(s3, bucket, prefix=""):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(
        Bucket=bucket, Prefix=prefix
    ):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return keys


def _create_instance_role(ctx, iam, role_name, bucket):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real b1 s3 events in sqs",
        Tags=[{"Key": "sim2real", "Value": "b1-s3-events-in-sqs"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ))
    # No sqs:* at all: the instance must be unable to write the queue itself, which is what makes
    # the 20 messages evidence about S3 firing rather than about the job.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-scope",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/in/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:DeleteObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/out/*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(_gone_ok(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-scope")
    ))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "b1-s3-events-in-sqs"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        )
    ))
    # IAM exposes no "this role is usable" condition to poll. RunInstances' own bounded retry on
    # InvalidParameterValue (see `_call_with_retry` below) is what makes this correct.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(10):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 9:
                raise
            time.sleep(5)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    for drop in (
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY),
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-scope"),
    ):
        try:
            drop()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    for attempt in range(10):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") == "DeleteConflict"
                and attempt < 9
            ):
                time.sleep(5)
                continue
            raise


def _terminate_and_wait(ec2, instance_id, timeout_s=420):
    ec2.terminate_instances(InstanceIds=[instance_id])
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [
            i["State"]["Name"]
            for r in _call_with_retry(
                lambda: ec2.describe_instances(InstanceIds=[instance_id]),
                codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                retries=12,
                delay=5.0,
            )["Reservations"]
            for i in r["Instances"]
        ]
        if all(s == "terminated" for s in states):
            return
        time.sleep(2)
    raise AssertionError(
        f"instance {instance_id} never reached terminated within {timeout_s}s"
    )


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_phase(ssm, instance_id, script, timeout_s=600):
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [script]},
            TimeoutSeconds=600,
            Comment="sim2real b1 s3 events job",
        )
    )
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll(
        _inv,
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=timeout_s,
        interval_s=5.0,
        what=f"invocation {command_id} reaching a terminal status",
    )


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return json.loads(lines[-1])


def _job_script(region, bucket):
    return f"""set -uo pipefail
export AWS_DEFAULT_REGION={region}
aws s3api get-object --bucket {bucket} --key {_SOURCE_KEY} /tmp/src >/dev/null 2>/tmp/get.err
GETRC=$?
if [ "$GETRC" != "0" ]; then cat /tmp/get.err >&2; exit "$GETRC"; fi
python3 - <<'GENEOF'
import hashlib, json
src = open("/tmp/src", "rb").read()
man = {{"_src_sha256": hashlib.sha256(src).hexdigest()}}
for i in range({_N}):
    nbytes = 1024 * (i + 1)
    digest = hashlib.sha256(src + str(i).encode()).digest()
    body = (digest * (nbytes // len(digest) + 1))[:nbytes]
    path = "/tmp/out-%02d" % i
    with open(path, "wb") as fh:
        fh.write(body)
    man["out/part-%02d" % i] = {{"size": nbytes,
                               "sha256": hashlib.sha256(body).hexdigest(),
                               "md5": hashlib.md5(body).hexdigest()}}
with open("/tmp/manifest.json", "w") as fh:
    json.dump(man, fh)
GENEOF
RC=0
for i in $(seq -w 0 {_N - 1}); do
  aws s3api put-object --bucket {bucket} --key "out/part-$i" --body "/tmp/out-$i" \
    >/dev/null 2>>/tmp/put.err || RC=1
done
if [ "$RC" != "0" ]; then cat /tmp/put.err >&2; exit "$RC"; fi
cat /tmp/manifest.json
"""


def _mutate_script(region, bucket, key):
    return f"""set -uo pipefail
export AWS_DEFAULT_REGION={region}
python3 - <<'GENEOF'
import hashlib, json
src = open("/tmp/src", "rb").read()
digest = hashlib.sha256(src + b"overwrite").digest()
body = (digest * ({_OVERWRITE_BYTES} // len(digest) + 1))[:{_OVERWRITE_BYTES}]
with open("/tmp/overwrite", "wb") as fh:
    fh.write(body)
with open("/tmp/mutate.json", "w") as fh:
    json.dump({{"size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
               "md5": hashlib.md5(body).hexdigest()}}, fh)
GENEOF
aws s3api put-object --bucket {bucket} --key "{key}" --body /tmp/overwrite >/dev/null
aws s3api delete-object --bucket {bucket} --key "{key}" >/dev/null
cat /tmp/mutate.json
"""


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
