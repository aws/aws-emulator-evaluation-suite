"""s3pointer-guest-reduces-the-whole-multipart-object-to-a-verified-checksum-and-leaves-nothing-on-failure."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "s3pointer-guest-reduces-the-whole-multipart-object-to-a-verified-checksum-and-leaves-nothing-on-failure"
)
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

_VPC_CIDR = "10.73.0.0/16"
_SUBNET_CIDR = "10.73.7.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")

_PART_BYTES = 5 * 1024 * 1024
#: 12 MiB uploaded as 5 + 5 + 2 MiB, so the object is genuinely multipart (ETag suffix `-3`) and a
#: guest that read only the first part would be one third short.
_PAYLOAD_BYTES = 12 * 1024 * 1024
_PARTS = 3
_INPUT_KEY = "input/payload.bin"
_DENIED_KEY = "denied/payload.bin"
_DENIED_BYTES = 4096
_MIB = 1024 * 1024


@tags(
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:happy-path",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A program on an EC2 instance, sent an SQS pointer, reduces the whole 12 MiB multipart object
    to the sha256/histogram this check recomputes and deletes the message; pointed at a key its
    role cannot read, it gets AccessDenied, leaves no result object, and the message is redelivered.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "queues": [], "rt": []}
    # Teardown runs in-band: terminating an instance and draining its ENI exceeds the 60 s
    # cleanup budget, so ctx.on_cleanup only holds the fast second net.
    try:
        _build(ctx, ec2, s3, sqs, ssm, iam, st)
        _assert_pointer_job(ctx, s3, sqs, ssm, st)
        _assert_denied_job_leaves_nothing(ctx, s3, sqs, ssm, st)
    finally:
        _teardown(ctx, ec2, s3, sqs, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, s3, sqs, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-s3ptr-job-")
    st["name"], st["region"] = name, region

    zone = _usable_zone(ec2)
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    _second_net(ctx, lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet)
    _second_net(ctx, lambda: ec2.delete_subnet(SubnetId=subnet))

    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(name)}]
    )["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw
    _second_net(ctx, lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    _second_net(
        ctx,
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    )

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(name)}],
    )["RouteTable"]["RouteTableId"]
    _second_net(ctx, lambda: ec2.delete_route_table(RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet)["AssociationId"]
    st["rt"].append((rt_id, assoc))
    _second_net(ctx, lambda: ec2.disassociate_route_table(AssociationId=assoc))

    sg = ec2.create_security_group(
        GroupName=name + "-host",
        Description="sim2real s3-pointer job host (egress only)",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    _second_net(ctx, lambda: ec2.delete_security_group(GroupId=sg))

    bucket = name + "-bkt"
    st["bucket"] = bucket
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    _second_net(ctx, lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})

    payload = _payload_bytes(name, _PAYLOAD_BYTES)
    st["payload"] = payload
    _multipart_put(ctx, s3, bucket, _INPUT_KEY, payload)
    head = s3.head_object(Bucket=bucket, Key=_INPUT_KEY)
    st["input_etag"] = head["ETag"].strip('"')
    assert head["ContentLength"] == _PAYLOAD_BYTES, (
        f"the input object is {head['ContentLength']!r} bytes, the check uploaded {_PAYLOAD_BYTES}"
    )
    assert st["input_etag"].endswith(f"-{_PARTS}"), (
        f"the input object must be a genuine {_PARTS}-part multipart upload, so its ETag must end "
        f"-{_PARTS}; S3 reports {st['input_etag']!r}"
    )
    # Exists, and is deliberately outside the prefix the instance role may read: the failure arm's
    # AccessDenied must be about authorization, not about an absent key.
    s3.put_object(Bucket=bucket, Key=_DENIED_KEY, Body=payload[:_DENIED_BYTES])
    assert s3.head_object(Bucket=bucket, Key=_DENIED_KEY)["ContentLength"] == _DENIED_BYTES, (
        f"the check's own read of {_DENIED_KEY!r} must succeed, or the failure arm would be "
        f"asserting absence rather than denial"
    )

    queue = sqs.create_queue(
        QueueName=name + "-jobs",
        Attributes={"VisibilityTimeout": "15", "ReceiveMessageWaitTimeSeconds": "5"},
        tags={"sim2real": "s3pointer-job"},
    )["QueueUrl"]
    st["queue"] = queue
    st["queues"].append(queue)
    _second_net(ctx, lambda: sqs.delete_queue(QueueUrl=queue))
    st["queue_arn"] = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name, bucket, st["queue_arn"])

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
                    "SubnetId": subnet,
                    "Groups": [sg],
                    "AssociatePublicIpAddress": True,
                }
            ],
            IamInstanceProfile={"Name": role_name},
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            TagSpecifications=[
                {"ResourceType": rt, "Tags": _tags_for(name)} for rt in ("instance", "volume")
            ],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=75,
        delay=2.0,
    )["Instances"][0]["InstanceId"]
    st["instance"] = instance_id
    st["account"] = ctx.account
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    _second_net(ctx, lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    info = _poll(
        lambda: _agent_view(ssm, instance_id),
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=_budget_s(ctx, 600),
        interval_s=1,
        what=f"the SSM agent on instance {instance_id} coming Online",
        ctx=ctx,
    )
    assert info["PingStatus"] == "Online", f"agent view was {info!r}"


# ===== the claim ============================================================
def _assert_pointer_job(ctx, s3, sqs, ssm, st) -> None:
    bucket, queue, payload = st["bucket"], st["queue"], st["payload"]
    want = _reduce(payload)
    job = st["name"] + "-ok"
    prefix = f"out/{job}/"

    _drain(sqs, queue)
    pointer = _pointer(job, bucket, _INPUT_KEY, prefix)
    assert len(pointer.encode()) < 1024, (
        f"the pointer body must be tiny -- that is the whole point of the pattern; it is "
        f"{len(pointer.encode())} bytes"
    )
    sqs.send_message(QueueUrl=queue, MessageBody=pointer)

    inv = _run_phase(ssm, st["instance"], _guest_script(st["region"], queue, visibility=300),
                     timeout_s=_budget_s(ctx, 600), ctx=ctx)
    man = _json_line(inv)
    assert inv["ResponseCode"] == 0, (
        f"the guest job failed: rc={inv['ResponseCode']!r} manifest={man!r} "
        f"stderr={inv['StandardErrorContent'][-600:]!r}"
    )
    assert man["job_id"] == job, (
        f"the guest processed job {man['job_id']!r}, the check enqueued {job!r}"
    )

    # --- the guest read the WHOLE multipart object, not one part -----------------------------
    assert man["size"] == _PAYLOAD_BYTES, (
        f"the guest hashed {man['size']!r} bytes; the object is {_PAYLOAD_BYTES} bytes, and a "
        f"single-part read would have been {_PART_BYTES}"
    )
    assert man["parts_count"] == _PARTS, (
        f"the guest's HeadObject --part-number 1 reports PartsCount {man['parts_count']!r}, the "
        f"check uploaded {_PARTS} parts"
    )
    assert man["part1_bytes"] == _PART_BYTES, (
        f"part 1 is {man['part1_bytes']!r} bytes by the guest's own read, the check uploaded "
        f"{_PART_BYTES}"
    )
    assert man["etag"] == st["input_etag"], (
        f"the guest's GetObject saw ETag {man['etag']!r}, S3 reports {st['input_etag']!r} for the "
        f"same key"
    )
    assert want["sha256"] != want["sha256_first_5mib"], (
        "the whole-object and first-part digests must differ, or the read-it-whole assertion could "
        "not distinguish a single-part read"
    )

    # --- the answer, recomputed here from the bytes this check generated ---------------------
    for field in ("sha256", "sha256_first_5mib", "sha256_last_1mib", "byte_sum", "zero_count"):
        assert man[field] == want[field], (
            f"the guest reduced the object to {field}={man[field]!r}; this check's own reduction of "
            f"the same bytes is {want[field]!r}"
        )

    # --- and the same answer READ BACK FROM S3, not from the guest's stdout ------------------
    stored = json.loads(_get_bytes(s3, bucket, prefix + "result.json"))
    assert stored == man, (
        f"the result object the guest wrote to S3 disagrees with what it printed: stored={stored!r} "
        f"stdout={man!r}"
    )
    hist = _get_bytes(s3, bucket, prefix + "hist.bin")
    assert hist == want["hist_bytes"], (
        f"the 256-bin histogram the guest wrote to S3 is not the reduction of these bytes: "
        f"{len(hist)} bytes, sha256 {hashlib.sha256(hist).hexdigest()!r}, expected sha256 "
        f"{want['hist_sha256']!r}"
    )
    assert man["hist_sha256"] == hashlib.sha256(hist).hexdigest(), (
        f"the guest reported hist_sha256 {man['hist_sha256']!r} for the object it stored, which "
        f"hashes to {hashlib.sha256(hist).hexdigest()!r}"
    )
    assert sorted(_list_keys(s3, bucket, prefix=prefix)) == [
        prefix + "hist.bin",
        prefix + "result.json",
    ], f"the job's output prefix holds {_list_keys(s3, bucket, prefix=prefix)!r}"

    # --- the guest deleted the message it finished ------------------------------------------
    left = _hold_empty(sqs, queue, seconds=5)
    assert left == [], (
        f"the guest completed the job, so it must have deleted the message; the queue redelivered "
        f"{left!r}"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=queue, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", (
        f"a second observable disagrees with the empty receive: ApproximateNumberOfMessages="
        f"{depth!r}"
    )
    st["ok_prefix"] = prefix


def _assert_denied_job_leaves_nothing(ctx, s3, sqs, ssm, st) -> None:
    bucket, queue = st["bucket"], st["queue"]
    job = st["name"] + "-denied"
    prefix = f"out/{job}/"
    sqs.send_message(QueueUrl=queue, MessageBody=_pointer(job, bucket, _DENIED_KEY, prefix))

    inv = _run_phase(ssm, st["instance"], _guest_script(st["region"], queue, visibility=3),
                     timeout_s=_budget_s(ctx, 600), ctx=ctx)
    man = _json_line(inv)
    assert man["job_id"] == job, (
        f"the guest processed job {man['job_id']!r}, the check enqueued {job!r}"
    )
    assert inv["ResponseCode"] == 3, (
        f"the guest must exit 3 on a refused read; rc={inv['ResponseCode']!r} manifest={man!r}"
    )
    assert inv["Status"] == "Failed", (
        f"an invocation whose command exited non-zero must be Failed; it is {inv['Status']!r}"
    )
    assert man["stage"] == "get", (
        f"the job must fail at the object read, not earlier or later; it failed at "
        f"{man['stage']!r} ({man.get('stderr_tail')!r})"
    )
    assert man["error_code"] == "AccessDenied", (
        f"reading {_DENIED_KEY!r} is outside the instance role's only S3 grant, so GetObject must "
        f"refuse it with AccessDenied; the guest saw {man['error_code']!r} "
        f"({man.get('stderr_tail')!r})"
    )
    expected_denial = (
        f"User: arn:aws:sts::{st['account']}:assumed-role/{st['role']}/{st['instance']} is not "
        f"authorized to perform: s3:GetObject on resource: \"arn:aws:s3:::{bucket}/{_DENIED_KEY}\" "
        f"because no identity-based policy allows the s3:GetObject action"
    )
    assert man["error_message"] == expected_denial, (
        f"GetObject's refusal must carry S3's exact message {expected_denial!r}; the guest saw "
        f"{man['error_message']!r}"
    )
    # HeadObject has no response body, so the same denial reaches the caller as a bare HTTP 403
    # with no error code in it, while GetObject carries `AccessDenied`.
    assert man["head_error_code"] == "403", (
        f"HeadObject on the same refused key must surface as a bare 403 -- it has no response body "
        f"to carry an error code; the guest saw {man['head_error_code']!r}"
    )

    # --- effect absent: no partial result, by two independent observables -------------------
    listed = _list_keys(s3, bucket, prefix=prefix)
    assert listed == [], (
        f"a failed job must leave NO result object behind; {prefix!r} holds {listed!r}"
    )
    gone = _error_code(lambda: s3.head_object(Bucket=bucket, Key=prefix + "result.json"))
    assert gone == "404", (
        f"HeadObject on the result the failed job would have written returned {gone!r}, not 404"
    )
    everything = _list_keys(s3, bucket, prefix="out/")
    assert sorted(everything) == [
        st["ok_prefix"] + "hist.bin",
        st["ok_prefix"] + "result.json",
    ], f"out/ holds {sorted(everything)!r}; only the successful job may have written"

    # --- and the message it never deleted comes back ----------------------------------------
    again = _receive_with_count(sqs, queue, timeout_s=_budget_s(ctx, 120), ctx=ctx)
    body = json.loads(again["Body"])
    assert body["job_id"] == job, (
        f"the unfinished message must return to the queue; what came back was {body!r}"
    )
    count = int(again["Attributes"]["ApproximateReceiveCount"])
    assert count >= 2, (
        f"the guest received the message and never deleted it, so this receive must be at least "
        f"the second; ApproximateReceiveCount is {count!r}"
    )
    sqs.delete_message(QueueUrl=queue, ReceiptHandle=again["ReceiptHandle"])


# ===== in-band teardown =====================================================
def _teardown(ctx, ec2, s3, sqs, iam, st) -> list:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises naming each one that failed on anything but an already-gone code.
    """
    left = []

    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    if st.get("instance"):
        _step("instance", lambda: _terminate_and_wait(
            ec2, st["instance"], timeout_s=_budget_s(ctx, 420)))
    if st.get("vpc"):
        _step(
            "eni-drain",
            lambda: _poll(
                lambda: _vpc_enis(ec2, st["vpc"]),
                lambda enis: enis == [],
                timeout_s=_budget_s(ctx, 300),
                interval_s=2,
                what=f"every ENI in {st['vpc']!r} draining",
            ),
        )
    if st.get("bucket"):
        _step("bucket", lambda: _empty_and_delete_bucket(s3, st["bucket"]))
    for q in st.get("queues", []):
        _step(f"queue {q}", lambda u=q: sqs.delete_queue(QueueUrl=u))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    for rt_id, assoc in st.get("rt", []):
        _step(f"rt-assoc {assoc}", lambda a=assoc: ec2.disassociate_route_table(AssociationId=a))
        _step(
            f"rt {rt_id}",
            lambda r=rt_id: _retry_dependency(lambda: ec2.delete_route_table(RouteTableId=r),
                                              timeout_s=_budget_s(ctx, 240)),
        )
    if st.get("igw"):
        _step(
            "igw-detach",
            lambda: _retry_dependency(
                lambda: ec2.detach_internet_gateway(
                    InternetGatewayId=st["igw"], VpcId=st["vpc"]
                ),
                timeout_s=_budget_s(ctx, 240),
            ),
        )
        _step(
            "igw",
            lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]),
        )
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s), timeout_s=_budget_s(ctx, 240)
        ))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s), timeout_s=_budget_s(ctx, 240)
        ))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"]),
                                               timeout_s=_budget_s(ctx, 240)))
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


def _second_net(ctx, fn):
    """Register a non-waiting cleanup net behind the in-band teardown. That teardown has normally
    removed the resource already, so a not-found answer here is the expected outcome."""
    def _quiet():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise
    ctx.on_cleanup(_quiet)

# ===== helpers ===============================================================


def _assert_vpc_gone(ec2, vpc) -> None:
    """Verified absence, not a delete that returned 200: raise while DescribeVpcs still lists it."""
    still = ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"]
    if still:
        raise AssertionError(f"vpc {vpc} is still describable: {still!r}")
_GONE_CODES = (
    "NoSuchEntity",
    "NoSuchBucket",
    "NoSuchUpload",
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidInstanceID.NotFound",
    "InvalidAssociationID.NotFound",
    "InvalidInternetGatewayID.NotFound",
    "Gateway.NotAttached",
    "AWS.SimpleQueueService.NonExistentQueue",
)


def _tags_for(name):
    return [
        {"Key": "Name", "Value": name},
        {"Key": "sim2real", "Value": "s3pointer-job"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _payload_bytes(nonce, n):
    """`n` deterministic bytes. Derived from a per-run nonce so two concurrent runs reduce
    different content and neither can pass on the other's answer."""
    buf = bytearray()
    i = 0
    while len(buf) < n:
        buf += hashlib.sha256((nonce + ":" + str(i)).encode()).digest()
        i += 1
    return bytes(buf[:n])


def _reduce(data):
    """The reduction the guest must reproduce, computed here from the bytes the check uploaded."""
    hist = [data.count(bytes([b])) for b in range(256)]
    hist_bytes = b"".join(struct.pack("<I", c) for c in hist)
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha256_first_5mib": hashlib.sha256(data[:_PART_BYTES]).hexdigest(),
        "sha256_last_1mib": hashlib.sha256(data[-_MIB:]).hexdigest(),
        "byte_sum": sum(data),
        "zero_count": hist[0],
        "hist_bytes": hist_bytes,
        "hist_sha256": hashlib.sha256(hist_bytes).hexdigest(),
    }


def _pointer(job, bucket, key, prefix):
    return json.dumps(
        {"job_id": job, "bucket": bucket, "key": key, "result_prefix": prefix, "op": "sha256+hist256"},
        sort_keys=True,
    )


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=1.0, what="", ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_dependency(fn, timeout_s=240, interval_s=2):
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
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _vpc_enis(ec2, vpc_id):
    return [
        e["NetworkInterfaceId"]
        for e in ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["NetworkInterfaces"]
    ]


def _multipart_put(ctx, s3, bucket, key, data):
    """Upload `data` as explicit 5 MiB parts, so the object's ETag carries the part count and a
    single-part read by the guest is a distinguishable outcome."""
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    _second_net(
        ctx,
        lambda: s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    )
    parts = []
    for i in range(0, len(data), _PART_BYTES):
        number = len(parts) + 1
        etag = s3.upload_part(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=number,
            Body=data[i : i + _PART_BYTES],
        )["ETag"]
        parts.append({"ETag": etag, "PartNumber": number})
    assert len(parts) == _PARTS, f"expected {_PARTS} parts, built {len(parts)}"
    s3.complete_multipart_upload(
        Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": parts}
    )


def _get_bytes(s3, bucket, key):
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _list_keys(s3, bucket, prefix=""):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return sorted(keys)


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for up in page.get("Uploads", []):
            s3.abort_multipart_upload(
                Bucket=bucket, Key=up["Key"], UploadId=up["UploadId"]
            )
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        victims = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if victims:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
    s3.delete_bucket(Bucket=bucket)


def _drain(sqs, url):
    out = []
    while True:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=30
        ).get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _hold_empty(sqs, url, seconds):
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1, VisibilityTimeout=30
        ).get("Messages", []):
            out.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _receive_with_count(sqs, url, timeout_s, ctx=None):
    """The first message the queue redelivers, with its ApproximateReceiveCount."""
    deadline = time.monotonic() + timeout_s
    while True:
        msgs = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=1,
            VisibilityTimeout=60,
            AttributeNames=["ApproximateReceiveCount"],
        ).get("Messages", [])
        if msgs:
            return msgs[0]
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"a redelivery on {url!r}: the run budget ended first; not graded")
            raise AssertionError(
                f"nothing was redelivered on {url!r} within {timeout_s}s -- an unfinished message "
                f"must return to the queue once its visibility timeout expires"
            )


def _create_instance_role(ctx, iam, role_name, bucket, queue_arn):
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
        Description="sim2real s3-pointer job host",
        Tags=[{"Key": "sim2real", "Value": "s3pointer-job"}],
    )
    _second_net(ctx, lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    _second_net(
        ctx,
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    )
    # Read is granted ONLY under input/: that single scope is what makes the failure arm's
    # AccessDenied a service decision rather than a branch in the guest program.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="job-scope",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/input/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/out/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "sqs:ReceiveMessage",
                            "sqs:DeleteMessage",
                            "sqs:GetQueueAttributes",
                        ],
                        "Resource": queue_arn,
                    },
                ],
            }
        ),
    )
    _second_net(ctx, lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="job-scope"))
    iam.create_instance_profile(
        InstanceProfileName=role_name, Tags=[{"Key": "sim2real", "Value": "s3pointer-job"}]
    )
    _second_net(ctx, lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    _second_net(
        ctx,
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        )
    )
    # IAM exposes no "this role is usable" condition to poll; RunInstances' own bounded retry on
    # InvalidParameterValue is what makes this correct.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(25):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 24:
                raise
            time.sleep(2)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    for drop in (
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY),
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="job-scope"),
    ):
        try:
            drop()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    for attempt in range(25):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DeleteConflict" and attempt < 24:
                time.sleep(2)
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
                retries=30,
                delay=2.0,
            )["Reservations"]
            for i in r["Instances"]
        ]
        if all(s == "terminated" for s in states):
            return
        time.sleep(2)
    raise AssertionError(f"instance {instance_id} never reached terminated within {timeout_s}s")


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_phase(ssm, instance_id, script, timeout_s=600, ctx=None):
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [script]},
            TimeoutSeconds=600,
            Comment="sim2real s3-pointer job",
        )
    )
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll(
        _inv,
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=timeout_s,
        interval_s=1.0,
        what=f"invocation {command_id} reaching a terminal status",
        ctx=ctx,
    )


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return json.loads(lines[-1])


#: The job program. It runs INSIDE the instance: it consumes the pointer message, reads the object
#: the pointer names, reduces it, writes the result back to S3 and only then deletes the message.
#: Placeholders rather than an f-string, because the body is dense with braces.
_GUEST = r'''
import hashlib, json, re, struct, subprocess, sys

REGION = "@@REGION@@"
QUEUE = "@@QUEUE@@"
VIS = "@@VIS@@"
PART = @@PART@@
MIB = @@MIB@@
OBJ = "/tmp/obj.bin"
HIST = "/tmp/hist.bin"
JOB = "?"


def aws(*args):
    return subprocess.run(["aws"] + list(args) + ["--region", REGION],
                          capture_output=True, text=True)


def code_of(err):
    m = re.search(r"An error occurred \(([^)]+)\)", err or "")
    return m.group(1) if m else "NoErrorCodeInStderr"


def message_of(err):
    m = re.search(r"An error occurred \([^)]+\) when calling the \w+ operation: ([^\n]*)",
                  err or "")
    return m.group(1) if m else None


def fail(stage, err, rc, head_code=""):
    print(json.dumps({"job_id": JOB, "stage": stage, "error_code": code_of(err),
                      "error_message": message_of(err),
                      "head_error_code": head_code,
                      "stderr_tail": (err or "")[-300:]}, sort_keys=True))
    sys.exit(rc)


r = aws("sqs", "receive-message", "--queue-url", QUEUE, "--max-number-of-messages", "1",
        "--wait-time-seconds", "20", "--visibility-timeout", VIS,
        "--attribute-names", "ApproximateReceiveCount")
if r.returncode != 0:
    fail("receive", r.stderr, 4)
msgs = (json.loads(r.stdout or "{}").get("Messages") or [])
if len(msgs) != 1:
    print(json.dumps({"job_id": JOB, "stage": "receive", "error_code": "NoMessage",
                      "n": len(msgs)}, sort_keys=True))
    sys.exit(5)
m = msgs[0]
body = json.loads(m["Body"])
JOB = body["job_id"]
BUCKET = body["bucket"]
KEY = body["key"]
PREFIX = body["result_prefix"]

h = aws("s3api", "head-object", "--bucket", BUCKET, "--key", KEY, "--part-number", "1")
HEAD_CODE = "" if h.returncode == 0 else code_of(h.stderr)
head = json.loads(h.stdout or "{}") if h.returncode == 0 else {}

# The read is attempted even when the metadata probe was refused, so the runner sees BOTH codes S3
# produces for one denial: HeadObject has no response body to carry an error code, GetObject does.
g = aws("s3api", "get-object", "--bucket", BUCKET, "--key", KEY, OBJ)
if g.returncode != 0:
    fail("get", g.stderr, 3, HEAD_CODE)
if HEAD_CODE:
    fail("head", h.stderr, 3, HEAD_CODE)
got = json.loads(g.stdout or "{}")

with open(OBJ, "rb") as fh:
    data = fh.read()
hist = [data.count(bytes([b])) for b in range(256)]
with open(HIST, "wb") as fh:
    fh.write(b"".join(struct.pack("<I", c) for c in hist))
with open(HIST, "rb") as fh:
    hist_bytes = fh.read()
man = {"job_id": JOB,
       "stage": "done",
       "size": len(data),
       "sha256": hashlib.sha256(data).hexdigest(),
       "sha256_first_5mib": hashlib.sha256(data[:PART]).hexdigest(),
       "sha256_last_1mib": hashlib.sha256(data[-MIB:]).hexdigest(),
       "byte_sum": sum(data),
       "zero_count": hist[0],
       "hist_sha256": hashlib.sha256(hist_bytes).hexdigest(),
       "parts_count": head.get("PartsCount"),
       "part1_bytes": head.get("ContentLength"),
       "etag": (got.get("ETag") or "").strip('"')}
with open("/tmp/result.json", "w") as fh:
    fh.write(json.dumps(man, sort_keys=True))

p = aws("s3api", "put-object", "--bucket", BUCKET, "--key", PREFIX + "result.json",
        "--body", "/tmp/result.json")
if p.returncode != 0:
    fail("put-result", p.stderr, 3)
p = aws("s3api", "put-object", "--bucket", BUCKET, "--key", PREFIX + "hist.bin",
        "--body", HIST)
if p.returncode != 0:
    fail("put-hist", p.stderr, 3)
d = aws("sqs", "delete-message", "--queue-url", QUEUE, "--receipt-handle", m["ReceiptHandle"])
if d.returncode != 0:
    fail("delete", d.stderr, 3)
print(json.dumps(man, sort_keys=True))
'''


def _guest_script(region, queue_url, visibility):
    guest = (
        _GUEST.replace("@@REGION@@", region)
        .replace("@@QUEUE@@", queue_url)
        .replace("@@VIS@@", str(visibility))
        .replace("@@PART@@", str(_PART_BYTES))
        .replace("@@MIB@@", str(_MIB))
    )
    return "set -uo pipefail\ncat > /tmp/job.py <<'JOBEOF'\n" + guest + "\nJOBEOF\npython3 /tmp/job.py\n"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
