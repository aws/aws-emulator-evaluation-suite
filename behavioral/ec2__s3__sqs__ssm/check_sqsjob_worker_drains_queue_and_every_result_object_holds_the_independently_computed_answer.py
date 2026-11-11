"""sqsjob-worker-drains-queue-and-every-result-object-holds-the-independently-computed-answer."""

from __future__ import annotations

import hashlib
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "sqsjob-worker-drains-queue-and-every-result-object-holds-the-independently-computed-answer"
)
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

_VPC_CIDR = "10.74.0.0/16"
_SUBNET_CIDR = "10.74.10.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_N_JOBS = 6
_VISIBILITY_S = 120


@tags("cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """A worker on an instance drains six SQS jobs and writes one result per message whose content
    equals the answer the check computed independently from the input bytes; the queue ends empty
    and no other result object exists.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "rt": [], "queues": []}
    try:
        _build(ctx, ec2, s3, sqs, ssm, iam, st)
        _assert_jobs(s3, sqs, ssm, st)
    finally:
        _teardown(ec2, s3, sqs, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, s3, sqs, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-sqsjob1-")
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

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(name)}]
    )["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ctx.on_cleanup(_gone_ok(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ))

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(name)}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw
    )
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)[
        "AssociationId"
    ]
    st["rt"].append((rt_id, assoc))
    ctx.on_cleanup(_gone_ok(lambda: ec2.disassociate_route_table(AssociationId=assoc)))

    sg = ec2.create_security_group(
        GroupName=name + "-worker",
        Description="sim2real sqs job worker host",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_security_group(GroupId=sg)))

    bucket = name + "-bkt"
    st["bucket"] = bucket
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
    )
    ctx.on_cleanup(_gone_ok(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})
    # Versioning is what makes "exactly one result per message" assertable per key rather than by
    # a count: a second write to the same key would add a version instead of hiding inside one.
    s3.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )

    queue_url = sqs.create_queue(
        QueueName=name + "-jobs",
        Attributes={
            "VisibilityTimeout": str(_VISIBILITY_S),
            "ReceiveMessageWaitTimeSeconds": "20",
        },
        tags={"sim2real": "sqsjob-worker-drains-queue"},
    )["QueueUrl"]
    st["queues"].append(queue_url)
    st["queue"] = queue_url
    ctx.on_cleanup(_gone_ok(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    st["jobs"] = _plan_jobs(st["nonce"])
    for job, spec in st["jobs"].items():
        s3.put_object(Bucket=bucket, Key=spec["input_key"], Body=spec["input"])
    st["sent"] = {}
    for job, spec in st["jobs"].items():
        st["sent"][job] = sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(
                {"job": job, "input_key": spec["input_key"], "salt": spec["salt"]}
            ),
        )["MessageId"]

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name, bucket, queue_arn)

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
                    "SubnetId": subnet_id,
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
        # IAM exposes no "this instance profile is usable" condition to poll; RunInstances answers
        # InvalidParameterValue until it is, so the bounded retry IS the propagation wait.
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
        what=f"the SSM agent on worker instance {instance_id} coming Online",
    )
    assert info["PingStatus"] == "Online", f"agent view was {info!r}"


# ===== the claim ============================================================
def _assert_jobs(s3, sqs, ssm, st) -> None:
    bucket, queue_url, jobs = st["bucket"], st["queue"], st["jobs"]

    inv = _run_phase(ssm, st["instance"], _worker_script(st["region"], bucket, queue_url))
    assert inv["ResponseCode"] == 0, (
        f"the worker failed on the host: rc={inv['ResponseCode']!r} "
        f"stderr={inv['StandardErrorContent'][-600:]!r}"
    )
    report = _json_line(inv)
    assert sorted(report["jobs"]) == sorted(jobs), (
        f"the worker reports having handled {sorted(report['jobs'])!r}; the check queued "
        f"{sorted(jobs)!r}"
    )

    for job, spec in sorted(jobs.items()):
        got = report["jobs"][job]
        assert got["errors"] == [], (
            f"the worker reported errors for {job!r}: {got['errors']!r}"
        )
        assert got["writes"] == 1, (
            f"{job!r} must produce exactly one result write; the worker reports "
            f"{got['writes']!r} (receives={got['receives']!r})"
        )
        assert got["deletes"] >= 1, (
            f"the worker must have deleted the message for {job!r}; it reports {got!r}"
        )
        assert got["message_ids"] == [st["sent"][job]], (
            f"the worker processed message ids {got['message_ids']!r} for {job!r}; send_message "
            f"returned {st['sent'][job]!r}"
        )
        assert got["sha256"] == spec["sha256"], (
            f"the worker reports sha256 {got['sha256']!r} for {job!r}; the check computes "
            f"{spec['sha256']!r} from the input bytes it generated and the salt it queued"
        )
        assert got["bytes"] == spec["bytes"], (
            f"the worker reports {got['bytes']!r} reduced bytes for {job!r}; the check computes "
            f"{spec['bytes']!r}"
        )

        body = s3.get_object(Bucket=bucket, Key=spec["result_key"])["Body"].read()
        assert body == spec["expected_body"], (
            f"the result object {spec['result_key']!r} holds {body!r}; the answer the check "
            f"computed independently is {spec['expected_body']!r}"
        )
        versions = _versions_of(s3, bucket, spec["result_key"])
        assert len(versions["versions"]) == 1, (
            f"{spec['result_key']!r} must carry exactly one version -- one message, one result; it "
            f"carries {versions['versions']!r}"
        )
        assert versions["delete_markers"] == [], (
            f"{spec['result_key']!r} carries delete markers {versions['delete_markers']!r}; the "
            f"worker has no s3:DeleteObject permission and must not have removed anything"
        )

    # The queue drained: both depth counters at zero, then two long polls that return nothing.
    attrs = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed",
            ],
        )["Attributes"],
        lambda a: {a[k] for k in a if k.startswith("Approximate")} == {"0"},
        timeout_s=300,
        interval_s=10,
        what="the job queue reporting zero visible, zero in-flight and zero delayed messages",
    )
    assert attrs["ApproximateNumberOfMessages"] == "0", attrs
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", attrs
    for _ in range(2):
        left = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=20
        ).get("Messages", [])
        assert left == [], (
            f"a long poll on the drained queue returned {[m.get('MessageId') for m in left]!r}; "
            f"every message was reported deleted by the worker"
        )

    # Exactly N results and no others. Scoped to the bucket this check created, so "and no others"
    # is a property of the query rather than of who else is running in this account.
    listed = _list_keys(s3, bucket)
    expected_keys = sorted(
        [spec["input_key"] for spec in jobs.values()]
        + [spec["result_key"] for spec in jobs.values()]
    )
    assert sorted(listed) == expected_keys, (
        f"the bucket holds {sorted(listed)!r}; it must hold exactly the {_N_JOBS} inputs the check "
        f"PUT and the {_N_JOBS} results the worker wrote: {expected_keys!r}"
    )
    results = _list_keys(s3, bucket, prefix="results/")
    assert len(results) == _N_JOBS, (
        f"{len(results)} objects under results/ ({sorted(results)!r}); exactly {_N_JOBS} are "
        f"expected, one per message"
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
    for sg in reversed(st.get("sgs", [])):
        _step(
            f"sg {sg}",
            lambda s=sg: _retry_dependency(lambda: ec2.delete_security_group(GroupId=s)),
        )
    for rt_id, assoc in st.get("rt", []):
        _step(
            f"rt-assoc {assoc}",
            lambda a=assoc: ec2.disassociate_route_table(AssociationId=a),
        )
        _step(
            f"rt {rt_id}",
            lambda r=rt_id: _retry_dependency(lambda: ec2.delete_route_table(RouteTableId=r)),
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
            lambda: _retry_dependency(
                lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"])
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


def _tags_for(name):
    return [
        {"Key": "Name", "Value": name},
        {"Key": "sim2real", "Value": "sqsjob-worker-drains-queue"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _input_bytes(nonce, job, nbytes):
    buf = b""
    i = 0
    while len(buf) < nbytes:
        buf += hashlib.sha256((nonce + ":" + job + ":" + str(i)).encode()).digest()
        i += 1
    return buf[:nbytes]


def _plan_jobs(nonce):
    """Every job's input bytes, salt and the ANSWER, all computed here from values the check owns.

    The guest can only reach the same digest by fetching the object and reducing it with the salt
    the message carries; it is never told the answer.
    """
    jobs = {}
    for i in range(_N_JOBS):
        job = "job-%02d" % i
        nbytes = 4096 * (i + 1)
        payload = _input_bytes(nonce, job, nbytes)
        salt = "%s:%s:salt" % (nonce, job)
        digest = hashlib.sha256(payload + salt.encode()).hexdigest()
        total = len(payload) + len(salt.encode())
        jobs[job] = {
            "input": payload,
            "input_key": "in/" + job,
            "result_key": "results/" + job + ".out",
            "salt": salt,
            "sha256": digest,
            "bytes": total,
            "expected_body": ("sha256=%s bytes=%d job=%s\n" % (digest, total, job)).encode(),
        }
    return jobs


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


def _vpc_enis(ec2, vpc_id):
    return [
        e["NetworkInterfaceId"]
        for e in ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["NetworkInterfaces"]
    ]


def _list_keys(s3, bucket, prefix=""):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return keys


def _versions_of(s3, bucket, key):
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(
        Bucket=bucket, Prefix=key
    ):
        versions += [v["VersionId"] for v in page.get("Versions", []) if v["Key"] == key]
        markers += [m["VersionId"] for m in page.get("DeleteMarkers", []) if m["Key"] == key]
    return {"versions": versions, "delete_markers": markers}


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
        Description="sim2real sqs job worker",
        Tags=[{"Key": "sim2real", "Value": "sqsjob-worker-drains-queue"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ))
    # No sqs:SendMessage, no s3:ListBucket, no s3:DeleteObject: the worker can only consume the
    # queue, read what the check PUT under in/ and write under results/.
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
                        "Resource": f"arn:aws:s3:::{bucket}/in/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/results/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
                        "Resource": queue_arn,
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(_gone_ok(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="job-scope")
    ))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "sqsjob-worker-drains-queue"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        )
    ))


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
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="job-scope"),
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
            if exc.response.get("Error", {}).get("Code") == "DeleteConflict" and attempt < 9:
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


def _run_phase(ssm, instance_id, script, timeout_s=900):
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [script]},
            TimeoutSeconds=600,
            Comment="sim2real sqs job worker",
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


_WORKER = r'''
import json, os, subprocess, sys, time

QUEUE = "__QUEUE__"
BUCKET = "__BUCKET__"
REGION = "__REGION__"


def aws(args):
    return subprocess.run(["aws"] + args + ["--region", REGION],
                          capture_output=True, text=True)


def receive():
    """Long poll, with a bounded retry: the instance profile's permissions become usable a moment
    after the host boots, and a transient refusal there is not an empty queue."""
    last = None
    for _ in range(6):
        r = aws(["sqs", "receive-message", "--queue-url", QUEUE,
                 "--max-number-of-messages", "10", "--wait-time-seconds", "20",
                 "--visibility-timeout", "__VISIBILITY__", "--output", "json"])
        if r.returncode == 0:
            out = r.stdout.strip()
            return json.loads(out).get("Messages", []) if out else [], None
        last = r.stderr.strip()[:400]
        time.sleep(5)
    return [], last


report = {"jobs": {}, "polls": 0, "receive_errors": []}
done = {}
empty = 0
deadline = time.time() + 240
while time.time() < deadline and empty < 2:
    msgs, err = receive()
    report["polls"] += 1
    if err is not None:
        report["receive_errors"].append(err)
        break
    if not msgs:
        empty += 1
        continue
    empty = 0
    for m in msgs:
        body = json.loads(m["Body"])
        job = body["job"]
        ent = report["jobs"].setdefault(job, {
            "message_ids": [], "receives": 0, "writes": 0, "deletes": 0,
            "duplicates": 0, "errors": []})
        ent["receives"] += 1
        if m["MessageId"] not in ent["message_ids"]:
            ent["message_ids"].append(m["MessageId"])
        if job in done:
            # A standard queue may deliver a message more than once. That is legal, so the worker
            # is idempotent: it records the redelivery, deletes it again and writes NO second
            # result.
            ent["duplicates"] += 1
            d = aws(["sqs", "delete-message", "--queue-url", QUEUE,
                     "--receipt-handle", m["ReceiptHandle"]])
            if d.returncode == 0:
                ent["deletes"] += 1
            continue
        g = aws(["s3api", "get-object", "--bucket", BUCKET, "--key", body["input_key"],
                 "/tmp/in"])
        if g.returncode != 0:
            ent["errors"].append({"stage": "get", "rc": g.returncode,
                                  "stderr": g.stderr.strip()[:400]})
            continue
        with open("/tmp/salt", "w") as fh:
            fh.write(body["salt"])
        with open("/tmp/cat", "wb") as out:
            for p in ("/tmp/in", "/tmp/salt"):
                with open(p, "rb") as fh:
                    out.write(fh.read())
        # coreutils, not hashlib: the runner's answer comes from a different implementation over a
        # different data path, so a shared bug cannot make both agree.
        h = subprocess.run(["sha256sum", "/tmp/cat"], capture_output=True, text=True)
        if h.returncode != 0:
            ent["errors"].append({"stage": "hash", "rc": h.returncode,
                                  "stderr": h.stderr.strip()[:400]})
            continue
        digest = h.stdout.split()[0]
        nbytes = os.path.getsize("/tmp/cat")
        with open("/tmp/result", "w") as fh:
            fh.write("sha256=%s bytes=%d job=%s\n" % (digest, nbytes, job))
        p = aws(["s3api", "put-object", "--bucket", BUCKET,
                 "--key", "results/" + job + ".out", "--body", "/tmp/result"])
        if p.returncode != 0:
            ent["errors"].append({"stage": "put", "rc": p.returncode,
                                  "stderr": p.stderr.strip()[:400]})
            continue
        ent["writes"] += 1
        ent["sha256"] = digest
        ent["bytes"] = nbytes
        done[job] = True
        d = aws(["sqs", "delete-message", "--queue-url", QUEUE,
                 "--receipt-handle", m["ReceiptHandle"]])
        if d.returncode == 0:
            ent["deletes"] += 1
        else:
            ent["errors"].append({"stage": "delete", "rc": d.returncode,
                                  "stderr": d.stderr.strip()[:400]})

sys.stdout.write(json.dumps(report) + "\n")
'''


def _worker_script(region, bucket, queue_url):
    """The worker, as the SSM command payload. The act this check grades happens HERE, inside the
    guest -- which is why the check carries `dp:native` and why nothing in this file imports a
    client for it."""
    worker = (
        _WORKER.replace("__QUEUE__", queue_url)
        .replace("__BUCKET__", bucket)
        .replace("__REGION__", region)
        .replace("__VISIBILITY__", str(_VISIBILITY_S))
    )
    return (
        "set -uo pipefail\n"
        f"export AWS_DEFAULT_REGION={region}\n"
        "cat >/tmp/worker.py <<'SIM2REALWORKEREOF'\n"
        f"{worker}\n"
        "SIM2REALWORKEREOF\n"
        "python3 /tmp/worker.py\n"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
