"""sqsrace-poisoned-job-writes-no-result-object-and-lands-in-dlq."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqsrace-poisoned-job-writes-no-result-object-and-lands-in-dlq"
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

_VPC_CIDR = "10.82.0.0/16"
_SUBNET_CIDR = "10.82.10.0/24"
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
_GOOD_JOBS = 3
_INPUT_BYTES = 4096
_VISIBILITY_S = 15
_MAX_RECEIVES = 2


# timing:real-time — visibility: 15 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """A job whose input object does not exist writes no result object and is not deleted, and
    after maxReceiveCount SQS redrives it to the DLQ byte-identical, while three well-formed jobs on
    the same queue each produce their one correct result as the positive control.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "queues": [], "instances": []}
    try:
        _build(ctx, ec2, s3, sqs, ssm, iam, st)
        _assert_rejection(s3, sqs, ssm, st)
    finally:
        _teardown(ec2, s3, sqs, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, s3, sqs, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-sqsrace-d-")
    st["name"], st["region"], st["nonce"] = name, region, name

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

    igw = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": _tags_for(name + "-igw")}
        ]
    )["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ctx.on_cleanup(_gone_ok(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ))

    subnet = _create_subnet(ctx, ec2, st, _SUBNET_CIDR, zone, name + "-public")
    rt_id = _create_route_table(ctx, ec2, st, subnet, name + "-rt")
    ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw
    )
    sg = _create_sg(ctx, ec2, st, name + "-worker", "sim2real sqs poison worker host")

    bucket = name + "-bkt"
    st["bucket"] = bucket
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
    )
    ctx.on_cleanup(_gone_ok(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})
    # Versioned so that "no result object was written" is a claim about the key's whole history and
    # not just about what a GET happens to return now.
    s3.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )

    st["good"] = ["job-%02d" % i for i in range(_GOOD_JOBS)]
    st["poison"] = "job-poison"
    st["inputs"] = {}
    for jid in st["good"]:
        data = _input_bytes(st["nonce"], jid)
        st["inputs"][jid] = data
        s3.put_object(Bucket=bucket, Key=_in_key(jid), Body=data)
    # The poisoned job's input object is deliberately never created. Its absence is what the guest
    # must be refused for.
    missing = _error_code(
        lambda: s3.head_object(Bucket=bucket, Key=_in_key(st["poison"]))
    )
    assert missing == "404", (
        f"the poisoned job's input {_in_key(st['poison'])!r} must not exist before the run; "
        f"HeadObject returned {missing!r}"
    )

    dlq = sqs.create_queue(
        QueueName=name + "-dlq", tags={"sim2real": "sqsrace-poison"}
    )["QueueUrl"]
    st["dlq"] = dlq
    st["queues"].append(dlq)
    ctx.on_cleanup(_gone_ok(lambda: sqs.delete_queue(QueueUrl=dlq)))
    queue = sqs.create_queue(
        QueueName=name + "-jobs",
        Attributes={
            "VisibilityTimeout": str(_VISIBILITY_S),
            "RedrivePolicy": json.dumps(
                {
                    "deadLetterTargetArn": _queue_arn(sqs, dlq),
                    "maxReceiveCount": str(_MAX_RECEIVES),
                }
            ),
        },
        tags={"sim2real": "sqsrace-poison"},
    )["QueueUrl"]
    st["queue"] = queue
    st["queues"].append(queue)
    ctx.on_cleanup(_gone_ok(lambda: sqs.delete_queue(QueueUrl=queue)))

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name, bucket, _queue_arn(sqs, queue))

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    instances = [
        i["InstanceId"]
        for i in _call_with_retry(
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
                    {"ResourceType": rt, "Tags": _tags_for(name)}
                    for rt in ("instance", "volume")
                ],
            ),
            codes=_THROTTLE + ("InvalidParameterValue",),
            retries=30,
            delay=5.0,
        )["Instances"]
    ]
    st["instances"] = instances
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(_gone_ok(lambda: ec2.terminate_instances(InstanceIds=instances)))
    info = _poll(
        lambda: _agent_view(ssm, instances[0]),
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=600,
        interval_s=10,
        what=f"the SSM agent on worker {instances[0]} coming Online",
    )
    assert info["PingStatus"] == "Online", f"agent view was {info!r}"


# ===== the claim ============================================================
def _assert_rejection(s3, sqs, ssm, st) -> None:
    bucket, queue, dlq, worker = st["bucket"], st["queue"], st["dlq"], st["instances"][0]
    jobs = st["good"] + [st["poison"]]

    assert _drain(sqs, queue) == [], (
        "the queue the check just created must be empty before any job is enqueued"
    )
    assert _drain(sqs, dlq) == [], "the dead letter queue must start empty"

    poison_body = _job_body(st["poison"])
    poison_id = sqs.send_message(QueueUrl=queue, MessageBody=poison_body)["MessageId"]
    for jid in st["good"]:
        sqs.send_message(QueueUrl=queue, MessageBody=_job_body(jid))

    invs = _run_phase(ssm, [worker], _worker_script(st["region"], bucket, queue))
    rep = _guest_json(invs, worker)
    assert rep["worker"] == worker, (
        f"the report read back names worker {rep['worker']!r}, not {worker!r}, so the guest's "
        f"stdout cannot be attributed"
    )

    # --- the rejection, as the guest saw it ---------------------------------
    rejects = [r for r in rep["rejected"] if r["job"] == st["poison"]]
    assert rejects, (
        f"the guest must have been refused the poisoned job's input; it reported {rep!r}"
    )
    codes = {_cli_error_code(r["err"]) for r in rejects}
    assert codes == {"NoSuchKey"}, (
        f"GetObject for the absent input {_in_key(st['poison'])!r} must be refused NoSuchKey; the "
        f"guest reported {codes!r} from {rejects!r}"
    )
    assert st["poison"] not in rep["wrote"], (
        f"the guest must not claim to have written the poisoned job; it reported "
        f"wrote={rep['wrote']!r}"
    )

    # --- the effect is ABSENT, not merely failed ----------------------------
    assert _versions(s3, bucket, _out_key(st["poison"])) == [], (
        f"the rejected job must have written NO result object at all -- the bucket is versioned and "
        f"holds {_versions(s3, bucket, _out_key(st['poison']))!r} for "
        f"{_out_key(st['poison'])!r}"
    )
    head = _error_code(lambda: s3.head_object(Bucket=bucket, Key=_out_key(st["poison"])))
    assert head == "404", (
        f"HeadObject for {_out_key(st['poison'])!r} must be refused 404, not return a zero-length "
        f"or partial object; it returned {head!r}"
    )
    assert sorted(_list_keys(s3, bucket, prefix="out/")) == sorted(
        _out_key(j) for j in st["good"]
    ), (
        f"only the well-formed jobs may have results; out/ holds "
        f"{sorted(_list_keys(s3, bucket, prefix='out/'))!r}"
    )

    # --- the positive control, in the same invocation ------------------------
    assert sorted(rep["wrote"]) == sorted(st["good"]), (
        f"the same guest code in the same invocation must have completed every well-formed job; it "
        f"reported wrote={rep['wrote']!r} for {st['good']!r}"
    )
    for jid in st["good"]:
        versions = _versions(s3, bucket, _out_key(jid))
        assert len(versions) == 1, (
            f"the control job {jid!r} must have exactly one result version; it has "
            f"{len(versions)}: {versions!r}"
        )
        want = _expected_result(jid, st["inputs"][jid], worker)
        got = s3.get_object(Bucket=bucket, Key=_out_key(jid))["Body"].read()
        assert got == want.encode(), (
            f"the result the guest wrote for {jid!r} is {got!r}; the check computed {want!r} "
            f"independently from the {_INPUT_BYTES} bytes it generated and PUT"
        )
        etag = s3.head_object(Bucket=bucket, Key=_out_key(jid))["ETag"].strip('"')
        assert etag == hashlib.md5(want.encode()).hexdigest(), (
            f"S3's ETag for {_out_key(jid)!r} is {etag!r}, the MD5 of the predicted result is "
            f"{hashlib.md5(want.encode()).hexdigest()!r}"
        )

    # --- the message itself is redriven, byte-identical ----------------------
    dead = _poll(
        lambda: _nudge_then_receive(sqs, queue, dlq),
        lambda msgs: len(msgs) >= 1,
        timeout_s=240,
        interval_s=5,
        what=f"the poisoned message reaching the dead letter queue after {_MAX_RECEIVES} receives",
    )
    assert len(dead) == 1, (
        f"exactly the poisoned message must be redriven; the DLQ returned {len(dead)}: "
        f"{[m['MessageId'] for m in dead]!r}"
    )
    assert dead[0]["MessageId"] == poison_id, (
        f"redrive must preserve the MessageId; the DLQ holds {dead[0]['MessageId']!r} and "
        f"SendMessage minted {poison_id!r}"
    )
    assert dead[0]["Body"] == poison_body, (
        f"redrive must preserve the body byte-for-byte; the DLQ holds {dead[0]['Body']!r} and the "
        f"check sent {poison_body!r}"
    )
    for m in dead:
        sqs.delete_message(QueueUrl=dlq, ReceiptHandle=m["ReceiptHandle"])

    drained = _poll(
        lambda: _queue_counts(sqs, queue),
        lambda c: c == ("0", "0"),
        timeout_s=180,
        interval_s=10,
        what="the main queue reporting nothing visible and nothing in flight",
    )
    assert drained == ("0", "0"), (
        f"every well-formed job was deleted and the poisoned one was redriven, so the main queue "
        f"must be empty; it reports visible/not-visible {drained!r}"
    )
    assert _drain(sqs, queue) == [], (
        f"a direct receive on the main queue must return nothing after the run of {jobs!r}"
    )


# ===== in-band teardown =====================================================
def _teardown(ec2, s3, sqs, iam, st) -> list:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises naming each one that failed on anything but an already-gone code."""
    left = []

    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    if st.get("instances"):
        _step("instances", lambda: _terminate_and_wait(ec2, st["instances"]))
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
    if st.get("igw"):
        _step(
            "igw-detach",
            lambda: _retry_dependency(
                lambda: ec2.detach_internet_gateway(
                    InternetGatewayId=st["igw"], VpcId=st["vpc"]
                )
            ),
        )
        _step("igw", lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]))
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
    "InvalidInternetGatewayID.NotFound",
    "Gateway.NotAttached",
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
_CLI_ERROR_RE = re.compile(r"An error occurred \(([A-Za-z0-9.]+)\)")


def _tags_for(name):
    return [
        {"Key": "Name", "Value": name},
        {"Key": "sim2real", "Value": "sqsrace-poison"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _in_key(jid):
    return "in/" + jid


def _out_key(jid):
    return "out/" + jid


def _job_body(jid):
    return json.dumps({"input": _in_key(jid), "job": jid}, sort_keys=True)


def _input_bytes(nonce, jid):
    buf = b""
    i = 0
    while len(buf) < _INPUT_BYTES:
        buf += hashlib.sha256((nonce + ":" + jid + ":" + str(i)).encode()).digest()
        i += 1
    return buf[:_INPUT_BYTES]


def _expected_result(jid, data, worker):
    """The result body the guest must produce, computed independently from the bytes the check
    generated and PUT -- never read back from the guest's own output."""
    return (
        json.dumps(
            {
                "bytesum": sum(data),
                "job": jid,
                "len": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "worker": worker,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _cli_error_code(stderr):
    """The exact AWS error code out of the CLI's `An error occurred (Code) when calling ...` line.
    Returns the whole stderr when there is no such line, so an unexpected shape can never be
    confused with a code."""
    m = _CLI_ERROR_RE.search(stderr or "")
    return m.group(1) if m else f"<no error code in {stderr!r}>"


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


def _queue_arn(sqs, url):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]


def _queue_counts(sqs, url):
    attrs = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
        ],
    )["Attributes"]
    return (
        attrs["ApproximateNumberOfMessages"],
        attrs["ApproximateNumberOfMessagesNotVisible"],
    )


def _drain(sqs, url, wait_s=2):
    """Receive and DELETE everything currently visible, returning the raw bodies."""
    out = []
    while True:
        msgs = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait_s,
            VisibilityTimeout=30,
        ).get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _nudge_then_receive(sqs, main_url, dlq_url):
    """SQS moves an over-delivered message to the dead letter queue on a RECEIVE attempt, so the
    worker exiting its poll loop must not be what decides whether the move ever happens. Attempt a
    receive on the main queue -- deleting NOTHING, and with a 1 s visibility so the attempt leaves no
    trace -- then read the DLQ."""
    sqs.receive_message(
        QueueUrl=main_url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=1,
        VisibilityTimeout=1,
    )
    return sqs.receive_message(
        QueueUrl=dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=10, VisibilityTimeout=30
    ).get("Messages", [])


def _versions(s3, bucket, key):
    """Every version id stored under exactly `key`, paginated because a prefix listing can also
    match longer keys."""
    out = []
    for page in s3.get_paginator("list_object_versions").paginate(
        Bucket=bucket, Prefix=key
    ):
        out += [v["VersionId"] for v in page.get("Versions", []) if v["Key"] == key]
        out += [
            "deletemarker:" + v["VersionId"]
            for v in page.get("DeleteMarkers", [])
            if v["Key"] == key
        ]
    return sorted(out)


def _list_keys(s3, bucket, prefix=""):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(
        Bucket=bucket, Prefix=prefix
    ):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return keys


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        victims = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if victims:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": victims})
    s3.delete_bucket(Bucket=bucket)


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
        Description="sim2real sqs poison worker",
        Tags=[{"Key": "sim2real", "Value": "sqsrace-poison"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ))
    # GetObject is allowed on the WHOLE `in/` prefix, so the poisoned job's refusal is about a key
    # that does not exist and not about the shape of the grant. `s3:ListBucket` is granted for the
    # same reason and it is load-bearing: S3 only tells a principal that a key is ABSENT if that
    # principal may list the bucket -- without it the same GET is refused as an authorization
    # answer instead, which would make this check measure the policy rather than the missing input.
    # Without s3:ListBucket, S3 answers a GetObject for a missing key with AccessDenied, not NoSuchKey.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="worker-scope",
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
                        "Action": ["s3:ListBucket"],
                        "Resource": f"arn:aws:s3:::{bucket}",
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
                            "sqs:ChangeMessageVisibility",
                            "sqs:GetQueueAttributes",
                        ],
                        "Resource": queue_arn,
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(_gone_ok(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="worker-scope")
    ))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "sqsrace-poison"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        )
    ))
    # IAM exposes no "this role is usable" condition to poll. RunInstances' own bounded retry on
    # InvalidParameterValue (see `_call_with_retry`) is what makes this correct.


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
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="worker-scope"),
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


def _terminate_and_wait(ec2, instance_ids, timeout_s=420):
    ec2.terminate_instances(InstanceIds=instance_ids)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [
            i["State"]["Name"]
            for r in _call_with_retry(
                lambda: ec2.describe_instances(InstanceIds=instance_ids),
                codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                retries=12,
                delay=5.0,
            )["Reservations"]
            for i in r["Instances"]
        ]
        if states and all(s == "terminated" for s in states):
            return
        time.sleep(10)
    raise AssertionError(
        f"instances {instance_ids!r} never reached terminated within {timeout_s}s"
    )


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_phase(ssm, instance_ids, script, timeout_s=900):
    """Run one shell script on every named instance and return the terminal invocation per host."""
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=list(instance_ids),
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [script]},
            TimeoutSeconds=600,
            Comment="sim2real sqs poison worker",
        ),
        codes=_THROTTLE + ("InvalidInstanceId",),
        retries=30,
        delay=5.0,
    )
    command_id = sent["Command"]["CommandId"]
    out = {}
    for iid in instance_ids:

        def _inv(iid=iid):
            try:
                return ssm.get_command_invocation(CommandId=command_id, InstanceId=iid)
            except ClientError as exc:
                if (
                    exc.response.get("Error", {}).get("Code")
                    == "InvocationDoesNotExist"
                ):
                    return None
                raise

        out[iid] = _poll(
            _inv,
            lambda i: i is not None and i.get("Status") in _TERMINAL,
            timeout_s=timeout_s,
            interval_s=5.0,
            what=f"invocation {command_id} on {iid} reaching a terminal status",
        )
    return out


def _guest_json(invocations, instance_id):
    """The last stdout line of one host's invocation, parsed. A non-zero guest rc is the failure."""
    inv = invocations[instance_id]
    assert inv["ResponseCode"] == 0, (
        f"the command on {instance_id} failed on the host: status={inv['Status']!r} "
        f"rc={inv['ResponseCode']!r} stderr={inv['StandardErrorContent'][-600:]!r}"
    )
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"{instance_id} reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return json.loads(lines[-1])


def _guest_header(region, extra):
    lines = ["set -uo pipefail", f"export AWS_DEFAULT_REGION={region}"]
    for key, value in extra.items():
        lines.append(f"export {key}='{value}'")
    lines += [
        'TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token"'
        ' -H "X-aws-ec2-metadata-token-ttl-seconds: 600")',
        'export SR_IID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN"'
        " http://169.254.169.254/latest/meta-data/instance-id)",
        "python3 - <<'SIM2REALPY'",
    ]
    return "\n".join(lines) + "\n"


def _guest_script(region, extra, body):
    return _guest_header(region, extra) + body + "\nSIM2REALPY\n"


_WORKER_PY = '''
import hashlib, json, os, subprocess, time


def aws(*args):
    return subprocess.run(["aws"] + list(args), capture_output=True, text=True, timeout=180)


BUCKET = os.environ["SR_BUCKET"]
QUEUE = os.environ["SR_QUEUE"]
IID = os.environ["SR_IID"]
VIS = os.environ["SR_VIS"]
IDLE_MAX = int(os.environ["SR_IDLE_MAX"])
report = {"worker": IID, "wrote": [], "dup": [], "rejected": [], "failed": [], "receives": 0}
idle = 0
end = time.monotonic() + float(os.environ["SR_DEADLINE"])
while time.monotonic() < end and idle < IDLE_MAX:
    r = aws("sqs", "receive-message", "--queue-url", QUEUE, "--max-number-of-messages", "1",
            "--wait-time-seconds", "10", "--visibility-timeout", VIS)
    if r.returncode != 0:
        report["failed"].append({"stage": "receive", "err": r.stderr.strip()[-300:]})
        break
    msgs = (json.loads(r.stdout) if r.stdout.strip() else {}).get("Messages", [])
    if not msgs:
        idle += 1
        continue
    idle = 0
    report["receives"] += 1
    m = msgs[0]
    job = json.loads(m["Body"])
    jid = job["job"]
    local = "/tmp/in-" + jid
    g = aws("s3api", "get-object", "--bucket", BUCKET, "--key", job["input"], local)
    if g.returncode != 0:
        # The input is not there. Write NOTHING and delete NOTHING: the message must be redriven.
        report["rejected"].append({"job": jid, "rc": g.returncode,
                                   "err": g.stderr.strip()[-400:]})
        continue
    with open(local, "rb") as fh:
        data = fh.read()
    result = {"bytesum": sum(data), "job": jid, "len": len(data),
              "sha256": hashlib.sha256(data).hexdigest(), "worker": IID}
    out_path = "/tmp/out-" + jid
    with open(out_path, "w") as fh:
        fh.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\\n")
    p = aws("s3api", "put-object", "--bucket", BUCKET, "--key", "out/" + jid,
            "--body", out_path, "--if-none-match", "*")
    if p.returncode == 0:
        report["wrote"].append(jid)
    elif "PreconditionFailed" in p.stderr:
        report["dup"].append(jid)
    else:
        report["failed"].append({"stage": "put", "job": jid, "err": p.stderr.strip()[-300:]})
        continue
    d = aws("sqs", "delete-message", "--queue-url", QUEUE, "--receipt-handle", m["ReceiptHandle"])
    if d.returncode != 0:
        report["failed"].append({"stage": "delete", "job": jid, "err": d.stderr.strip()[-300:]})
print(json.dumps(report))
'''


def _worker_script(region, bucket, queue):
    return _guest_script(
        region,
        {
            "SR_BUCKET": bucket,
            "SR_QUEUE": queue,
            "SR_VIS": str(_VISIBILITY_S),
            "SR_IDLE_MAX": "6",
            "SR_DEADLINE": "300",
        },
        _WORKER_PY,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
