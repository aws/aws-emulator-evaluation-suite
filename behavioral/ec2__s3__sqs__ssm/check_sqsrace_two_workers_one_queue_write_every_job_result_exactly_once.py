"""sqsrace-two-workers-one-queue-write-every-job-result-exactly-once."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqsrace-two-workers-one-queue-write-every-job-result-exactly-once"
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

_VPC_CIDR = "10.81.0.0/16"
_SUBNET_CIDR = "10.81.10.0/24"
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
_N_JOBS = 12
_INPUT_BYTES = 4096
_HOLD_VISIBILITY_S = 900
_WORK_VISIBILITY_S = 90
_BOGUS_HANDLE = "sim2real-not-a-receipt-handle"
_BAD_HANDLE_MSG = "The input receipt handle is invalid."
_PRECONDITION_MSG = "At least one of the pre-conditions you specified did not hold"


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
    """Two EC2 workers polling one SQS queue write every job's correct result to S3 exactly once,
    and a message held in flight by one worker is invisible to the other until it is released.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "queues": [], "instances": []}
    # Teardown runs in-band: registered cleanups get too little time for two instances to
    # terminate before the subnet and VPC can go.
    try:
        _build(ctx, ec2, s3, sqs, ssm, iam, st)
        _assert_partition(s3, sqs, ssm, st)
    finally:
        _teardown(ec2, s3, sqs, iam, st)


def _build(ctx, ec2, s3, sqs, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-sqsrace-p-")
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
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id))
    )

    subnet = _create_subnet(ctx, ec2, st, _SUBNET_CIDR, zone, name + "-public")
    rt_id = _create_route_table(ctx, ec2, st, subnet, name + "-rt")
    ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw
    )
    sg = _create_sg(ctx, ec2, st, name + "-worker", "sim2real sqs race worker hosts")

    bucket = name + "-bkt"
    st["bucket"] = bucket
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
    )
    ctx.on_cleanup(_gone_ok(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})
    # Versioning is the instrument: a SECOND write of a result key would add a version rather than
    # replacing one, so "exactly once" becomes an observable property of the object's history.
    s3.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )

    st["jobs"] = ["job-%02d" % i for i in range(_N_JOBS)]
    st["inputs"] = {}
    for jid in st["jobs"]:
        data = _input_bytes(st["nonce"], jid)
        st["inputs"][jid] = data
        s3.put_object(Bucket=bucket, Key=_in_key(jid), Body=data)

    queue = sqs.create_queue(
        QueueName=name + "-jobs",
        Attributes={"VisibilityTimeout": str(_WORK_VISIBILITY_S)},
        tags={"sim2real": "sqsrace-partition"},
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
                MinCount=2,
                MaxCount=2,
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
    # Registered before any readiness poll, so a host that never comes Online is still terminated.
    ctx.on_cleanup(_gone_ok(lambda: ec2.terminate_instances(InstanceIds=instances)))
    assert len(instances) == 2, f"expected two worker hosts, got {instances!r}"
    for iid in instances:
        info = _poll(
            lambda iid=iid: _agent_view(ssm, iid),
            lambda i: i is not None and i.get("PingStatus") == "Online",
            timeout_s=600,
            interval_s=10,
            what=f"the SSM agent on worker {iid} coming Online",
        )
        assert info["PingStatus"] == "Online", f"agent view for {iid} was {info!r}"


def _assert_partition(s3, sqs, ssm, st) -> None:
    bucket, queue = st["bucket"], st["queue"]
    worker_a, worker_b = st["instances"]
    region = st["region"]

    assert _drain(sqs, queue) == [], (
        "the queue the check just created must be empty before any job is enqueued"
    )

    # A held message is invisible to the other worker.
    first = st["jobs"][0]
    sent = sqs.send_message(QueueUrl=queue, MessageBody=_job_body(first))
    held_id = sent["MessageId"]

    hold = _guest_json(
        _run_phase(ssm, [worker_a], _hold_script(region, queue, _HOLD_VISIBILITY_S)),
        worker_a,
    )
    assert hold.get("message_id") == held_id, (
        f"worker A must receive the only message on the queue; it reported {hold!r} while "
        f"SendMessage minted {held_id!r}"
    )
    assert json.loads(hold["body"]) == json.loads(_job_body(first)), (
        f"worker A received body {hold['body']!r}, the check sent {_job_body(first)!r}"
    )
    receipt = hold["receipt"]
    assert receipt, f"worker A reported no receipt handle: {hold!r}"

    inflight = _poll(
        lambda: _queue_counts(sqs, queue),
        lambda c: c == ("0", "1"),
        timeout_s=120,
        interval_s=5,
        what="the queue reporting the held message as in-flight and nothing visible",
    )
    assert inflight == ("0", "1"), (
        f"while worker A holds the message the queue must report 0 visible and 1 not-visible; it "
        f"reports {inflight!r}"
    )

    blind = _guest_json(
        _run_phase(ssm, [worker_b], _probe_script(region, queue, attempts=3, wait_s=10)),
        worker_b,
    )
    assert blind["ids"] == [], (
        f"worker B long-polled the same queue 3 times while worker A held {held_id!r} and must "
        f"receive NOTHING; it received {blind!r}"
    )

    # A malformed receipt handle is refused and releases nothing.
    refused = _error(
        lambda: sqs.change_message_visibility(
            QueueUrl=queue, ReceiptHandle=_BOGUS_HANDLE, VisibilityTimeout=0
        )
    )
    assert refused == ("ReceiptHandleIsInvalid", _BAD_HANDLE_MSG), (
        f"ChangeMessageVisibility with a malformed receipt handle must be refused "
        f"ReceiptHandleIsInvalid {_BAD_HANDLE_MSG!r}; it returned {refused!r}"
    )
    still_blind = _guest_json(
        _run_phase(ssm, [worker_b], _probe_script(region, queue, attempts=2, wait_s=10)),
        worker_b,
    )
    assert still_blind["ids"] == [], (
        f"the refused ChangeMessageVisibility must have released nothing, so worker B must still "
        f"receive nothing; it received {still_blind!r}"
    )
    assert _list_keys(s3, bucket, prefix="out/") == [], (
        "no result object may exist before any worker has processed a job"
    )

    # The guest's own release, with the real handle, is the control.
    released = _guest_json(
        _run_phase(ssm, [worker_a], _release_script(region, queue, receipt)), worker_a
    )
    assert _cli_error(released["bad_err"]) == ("ReceiptHandleIsInvalid", _BAD_HANDLE_MSG), (
        f"the guest's ChangeMessageVisibility with a malformed handle must report "
        f"ReceiptHandleIsInvalid {_BAD_HANDLE_MSG!r}; it reported rc={released['bad_rc']!r} "
        f"stderr={released['bad_err']!r}"
    )
    assert released["good_rc"] == 0, (
        f"the same call with the receipt handle worker A actually holds is the positive control and "
        f"must succeed; it reported rc={released['good_rc']!r} stderr={released['good_err']!r}"
    )
    seen_again = _guest_json(
        _run_phase(ssm, [worker_b], _probe_script(region, queue, attempts=3, wait_s=10)),
        worker_b,
    )
    # Each probe receive passes `--visibility-timeout 0`, so the released message stays visible and
    # a later attempt may legitimately see it again. The claim is WHICH message B can now see.
    assert set(seen_again["ids"]) == {held_id}, (
        f"once worker A sets the visibility timeout to 0, worker B must receive the SAME message; "
        f"it received {seen_again!r} and the held id was {held_id!r}"
    )

    # The race. Delivery is at-least-once, so only the effect is asserted, per job: each worker
    # writes with If-None-Match: *, which S3 resolves atomically.
    for jid in st["jobs"][1:]:
        sqs.send_message(QueueUrl=queue, MessageBody=_job_body(jid))

    invs = _run_phase(ssm, st["instances"], _worker_script(region, bucket, queue))
    reports = {iid: _guest_json(invs, iid) for iid in st["instances"]}
    for iid, rep in reports.items():
        assert rep["worker"] == iid, (
            f"the report read back from {iid} names worker {rep['worker']!r}, so the two guests' "
            f"stdout cannot be attributed"
        )
        assert rep["failed"] == [], (
            f"worker {iid} reported failed stages: {rep['failed']!r}"
        )
    wrote = {iid: rep["wrote"] for iid, rep in reports.items()}
    union = [jid for lst in wrote.values() for jid in lst]
    assert sorted(union) == sorted(st["jobs"]), (
        f"the union of what the two workers wrote must cover every job exactly once; the workers "
        f"claim {wrote!r} for jobs {st['jobs']!r}"
    )
    assert len(union) == len(set(union)), (
        f"no job may be written by both workers -- S3's conditional PutObject makes that "
        f"impossible, so this would be a fidelity defect; the workers claim {wrote!r}"
    )
    claimant = {jid: iid for iid, lst in wrote.items() for jid in lst}

    for jid in st["jobs"]:
        versions = _versions(s3, bucket, _out_key(jid))
        assert len(versions) == 1, (
            f"the result object for {jid!r} must have been written EXACTLY once; the bucket is "
            f"versioned and holds {len(versions)} versions of {_out_key(jid)!r}: {versions!r}"
        )
        want = _expected_result(jid, st["inputs"][jid], claimant[jid])
        got = s3.get_object(Bucket=bucket, Key=_out_key(jid))["Body"].read()
        assert got == want.encode(), (
            f"the result the guest wrote for {jid!r} is {got!r}; the check computed {want!r} "
            f"independently from the {_INPUT_BYTES} bytes it generated and PUT"
        )
        head = s3.head_object(Bucket=bucket, Key=_out_key(jid))
        assert head["ETag"].strip('"') == hashlib.md5(want.encode()).hexdigest(), (
            f"S3's ETag for {_out_key(jid)!r} is {head['ETag']!r}, the MD5 of the predicted result "
            f"is {hashlib.md5(want.encode()).hexdigest()!r}"
        )
    assert sorted(_list_keys(s3, bucket, prefix="out/")) == sorted(
        _out_key(j) for j in st["jobs"]
    ), (
        f"the bucket holds {sorted(_list_keys(s3, bucket, prefix='out/'))!r} under out/, the jobs "
        f"were {sorted(_out_key(j) for j in st['jobs'])!r}"
    )

    drained = _poll(
        lambda: _queue_counts(sqs, queue),
        lambda c: c == ("0", "0"),
        timeout_s=180,
        interval_s=10,
        what="the queue reporting nothing visible and nothing in flight after the race",
    )
    assert drained == ("0", "0"), (
        f"every job was written, so every message must have been deleted; the queue reports "
        f"visible/not-visible {drained!r}"
    )
    assert _drain(sqs, queue) == [], (
        "a direct receive after the race must return no message at all"
    )

    # A second conditional write of one key is refused.
    repeat_job = st["jobs"][0]
    before = _versions(s3, bucket, _out_key(repeat_job))
    repeat = _guest_json(
        _run_phase(ssm, [worker_a], _repeat_script(region, bucket, repeat_job)), worker_a
    )
    assert _cli_error(repeat["err"]) == ("PreconditionFailed", _PRECONDITION_MSG), (
        f"re-writing {_out_key(repeat_job)!r} with If-None-Match:* must be refused "
        f"PreconditionFailed {_PRECONDITION_MSG!r} -- that refusal is what makes the effect exactly-once rather than "
        f"lucky; the guest reported rc={repeat['rc']!r} stderr={repeat['err']!r}"
    )
    after = _versions(s3, bucket, _out_key(repeat_job))
    assert after == before and len(after) == 1, (
        f"the refused write must leave the object untouched; versions were {before!r} and are now "
        f"{after!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=_out_key(repeat_job))["Body"].read()
    assert body == _expected_result(
        repeat_job, st["inputs"][repeat_job], claimant[repeat_job]
    ).encode(), (
        f"the refused write must not have changed the stored bytes of {_out_key(repeat_job)!r}; "
        f"they are now {body!r}"
    )


def _teardown(ec2, s3, sqs, iam, st) -> list:
    """Ordered teardown with waits. Runs every step, then raises naming each one that failed on
    anything but an already-gone code."""
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
        _step(
            "igw",
            lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]),
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
    "QueueDoesNotExist",
)


def _gone_ok(fn):
    """A cleanup step that tolerates the resource being gone already."""

    def step():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise

    return step
_CLI_ERROR_RE = re.compile(r"An error occurred \(([A-Za-z0-9.]+)\) when calling the \w+ operation: (.*)")


def _tags_for(name):
    return [
        {"Key": "Name", "Value": name},
        {"Key": "sim2real", "Value": "sqsrace-partition"},
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
    """The result body the guest must produce, computed independently from the input bytes."""
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


def _cli_error(stderr):
    """The (code, message) from the CLI's `An error occurred (Code) ...: Message` line.

    Returns the whole stderr when there is no such line."""
    m = _CLI_ERROR_RE.search(stderr or "")
    return (m.group(1), m.group(2).strip()) if m else f"<no error line in {stderr!r}>"


def _error(fn):
    """The (code, message) of the ClientError raised by fn; raise if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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


def _versions(s3, bucket, key):
    """Every version id stored under exactly `key`, paginated."""
    out = []
    for page in s3.get_paginator("list_object_versions").paginate(
        Bucket=bucket, Prefix=key
    ):
        out += [
            v["VersionId"] for v in page.get("Versions", []) if v["Key"] == key
        ]
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
        Description="sim2real sqs race worker",
        Tags=[{"Key": "sim2real", "Value": "sqsrace-partition"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY))
    )
    # No `sqs:SendMessage` at all: the workers can consume the queue but can never enqueue, which
    # is what makes every message on it one the CHECK sent.
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
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="worker-scope"))
    )
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "sqsrace-partition"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        ))
    )
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
        time.sleep(2)
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
            Comment="sim2real sqs race worker",
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
    lines = [
        "set -uo pipefail",
        f"export AWS_DEFAULT_REGION={region}",
    ]
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


_AWS_HELPER = '''
import hashlib, json, os, subprocess, time


def aws(*args):
    return subprocess.run(["aws"] + list(args), capture_output=True, text=True, timeout=180)
'''

_HOLD_PY = _AWS_HELPER + '''
QUEUE = os.environ["SR_QUEUE"]
out = {"worker": os.environ["SR_IID"], "attempts": 0}
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    r = aws("sqs", "receive-message", "--queue-url", QUEUE, "--max-number-of-messages", "1",
            "--wait-time-seconds", "10", "--visibility-timeout", os.environ["SR_VIS"])
    out["attempts"] += 1
    if r.returncode != 0:
        out["error"] = r.stderr.strip()[-300:]
        break
    msgs = (json.loads(r.stdout) if r.stdout.strip() else {}).get("Messages", [])
    if msgs:
        out["message_id"] = msgs[0]["MessageId"]
        out["body"] = msgs[0]["Body"]
        out["receipt"] = msgs[0]["ReceiptHandle"]
        break
print(json.dumps(out))
'''

_PROBE_PY = _AWS_HELPER + '''
QUEUE = os.environ["SR_QUEUE"]
out = {"worker": os.environ["SR_IID"], "counts": [], "ids": []}
for _ in range(int(os.environ["SR_ATTEMPTS"])):
    r = aws("sqs", "receive-message", "--queue-url", QUEUE, "--max-number-of-messages", "10",
            "--wait-time-seconds", os.environ["SR_WAIT"], "--visibility-timeout", "0")
    if r.returncode != 0:
        out["error"] = r.stderr.strip()[-300:]
        break
    msgs = (json.loads(r.stdout) if r.stdout.strip() else {}).get("Messages", [])
    out["counts"].append(len(msgs))
    out["ids"] += [m["MessageId"] for m in msgs]
print(json.dumps(out))
'''

_RELEASE_PY = _AWS_HELPER + '''
QUEUE = os.environ["SR_QUEUE"]
out = {"worker": os.environ["SR_IID"]}
bad = aws("sqs", "change-message-visibility", "--queue-url", QUEUE,
          "--receipt-handle", os.environ["SR_BOGUS"], "--visibility-timeout", "0")
out["bad_rc"], out["bad_err"] = bad.returncode, bad.stderr.strip()[-400:]
good = aws("sqs", "change-message-visibility", "--queue-url", QUEUE,
           "--receipt-handle", os.environ["SR_RECEIPT"], "--visibility-timeout", "0")
out["good_rc"], out["good_err"] = good.returncode, good.stderr.strip()[-400:]
print(json.dumps(out))
'''

_WORKER_PY = _AWS_HELPER + '''
BUCKET = os.environ["SR_BUCKET"]
QUEUE = os.environ["SR_QUEUE"]
IID = os.environ["SR_IID"]
VIS = os.environ["SR_VIS"]
IDLE_MAX = int(os.environ["SR_IDLE_MAX"])
report = {"worker": IID, "wrote": [], "dup": [], "failed": [], "receives": 0}
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
        report["failed"].append({"stage": "get", "job": jid, "err": g.stderr.strip()[-300:]})
        continue
    with open(local, "rb") as fh:
        data = fh.read()
    result = {"bytesum": sum(data), "job": jid, "len": len(data),
              "sha256": hashlib.sha256(data).hexdigest(), "worker": IID}
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\\n"
    out_path = "/tmp/out-" + jid
    with open(out_path, "w") as fh:
        fh.write(payload)
    p = aws("s3api", "put-object", "--bucket", BUCKET, "--key", "out/" + jid,
            "--body", out_path, "--if-none-match", "*")
    if p.returncode == 0:
        report["wrote"].append(jid)
    elif "PreconditionFailed" in p.stderr:
        # An at-least-once redelivery of a job another worker already finished. S3 resolved the
        # race, so the EFFECT stays exactly-once; the message is still ours to delete.
        report["dup"].append(jid)
    else:
        report["failed"].append({"stage": "put", "job": jid, "err": p.stderr.strip()[-300:]})
        continue
    d = aws("sqs", "delete-message", "--queue-url", QUEUE, "--receipt-handle", m["ReceiptHandle"])
    if d.returncode != 0:
        report["failed"].append({"stage": "delete", "job": jid, "err": d.stderr.strip()[-300:]})
print(json.dumps(report))
'''

_REPEAT_PY = _AWS_HELPER + '''
BUCKET = os.environ["SR_BUCKET"]
JID = os.environ["SR_JOB"]
local = "/tmp/again-in-" + JID
g = aws("s3api", "get-object", "--bucket", BUCKET, "--key", "in/" + JID, local)
out = {"worker": os.environ["SR_IID"], "get_rc": g.returncode}
with open(local, "rb") as fh:
    data = fh.read()
result = {"bytesum": sum(data), "job": JID, "len": len(data),
          "sha256": hashlib.sha256(data).hexdigest(), "worker": os.environ["SR_IID"]}
path = "/tmp/again-out-" + JID
with open(path, "w") as fh:
    fh.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\\n")
p = aws("s3api", "put-object", "--bucket", BUCKET, "--key", "out/" + JID,
        "--body", path, "--if-none-match", "*")
out["rc"], out["err"] = p.returncode, p.stderr.strip()[-400:]
print(json.dumps(out))
'''


def _hold_script(region, queue, visibility_s):
    return _guest_script(
        region, {"SR_QUEUE": queue, "SR_VIS": str(visibility_s)}, _HOLD_PY
    )


def _probe_script(region, queue, attempts, wait_s):
    return _guest_script(
        region,
        {"SR_QUEUE": queue, "SR_ATTEMPTS": str(attempts), "SR_WAIT": str(wait_s)},
        _PROBE_PY,
    )


def _release_script(region, queue, receipt):
    return _guest_script(
        region,
        {"SR_QUEUE": queue, "SR_RECEIPT": receipt, "SR_BOGUS": _BOGUS_HANDLE},
        _RELEASE_PY,
    )


def _worker_script(region, bucket, queue):
    return _guest_script(
        region,
        {
            "SR_BUCKET": bucket,
            "SR_QUEUE": queue,
            "SR_VIS": str(_WORK_VISIBILITY_S),
            "SR_IDLE_MAX": "4",
            "SR_DEADLINE": "300",
        },
        _WORKER_PY,
    )


def _repeat_script(region, bucket, jid):
    return _guest_script(
        region, {"SR_BUCKET": bucket, "SR_JOB": jid}, _REPEAT_PY
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
