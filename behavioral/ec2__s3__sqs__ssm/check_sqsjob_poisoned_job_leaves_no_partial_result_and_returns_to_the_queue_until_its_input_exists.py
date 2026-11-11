"""sqsjob-poisoned-job-leaves-no-partial-result-and-returns-to-the-queue-until-its-input-exists."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "sqsjob-poisoned-job-leaves-no-partial-result-and-returns-to-the-queue-until-its-input-exists"
)
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

_VPC_CIDR = "10.75.0.0/16"
_SUBNET_CIDR = "10.75.10.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GOOD_JOBS = ("good-00", "good-01")
_POISON_JOB = "poison-00"
_VISIBILITY_S = 10
_CLI_ERROR_RE = re.compile(r"An error occurred \(([A-Za-z0-9.]+)\) when calling the \w+ operation: (.*)")


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A worker refused a job's missing input (AccessDenied to it, NoSuchKey to the owner) leaves no
    result, version or delete marker; the message returns after its visibility timeout, and once
    the input exists a re-run produces the right answer and drains the queue.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "rt": [], "queues": []}
    try:
        _build(ctx, ec2, s3, sqs, ssm, iam, st)
        _assert_poison_refused(ctx, s3, sqs, ssm, st)
        _assert_repair(ctx, s3, sqs, ssm, st)
    finally:
        # In-band: on_cleanup's 60 s budget cannot wait out termination and the ENI drain.
        _teardown(ctx, ec2, s3, sqs, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, s3, sqs, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-sqsjob2-")
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
    ctx.on_cleanup(_gone_ok(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)))

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(name)}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    st["rt"].append((rt_id, assoc))
    ctx.on_cleanup(_gone_ok(lambda: ec2.disassociate_route_table(AssociationId=assoc)))

    sg = ec2.create_security_group(
        GroupName=name + "-worker",
        Description="sim2real sqs poisoned job worker host",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_security_group(GroupId=sg)))

    bucket = name + "-bkt"
    st["bucket"] = bucket
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(_gone_ok(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})
    # Versioning makes "no partial result was left behind" assertable as the absence of any
    # version, which a plain HeadObject 404 alone cannot distinguish from a write-then-overwrite.
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    queue_url = sqs.create_queue(
        QueueName=name + "-jobs",
        Attributes={
            "VisibilityTimeout": str(_VISIBILITY_S),
            "ReceiveMessageWaitTimeSeconds": "20",
        },
        tags={"sim2real": "sqsjob-poisoned-job-leaves-no-partial-result"},
    )["QueueUrl"]
    st["queues"].append(queue_url)
    st["queue"] = queue_url
    ctx.on_cleanup(_gone_ok(lambda: sqs.delete_queue(QueueUrl=queue_url)))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    st["jobs"] = _plan_jobs(st["nonce"])
    # The poisoned job's input is deliberately never PUT; the two good jobs are the positive control.
    for job in _GOOD_JOBS:
        spec = st["jobs"][job]
        s3.put_object(Bucket=bucket, Key=spec["input_key"], Body=spec["input"])
    st["sent"] = {}
    for job in list(_GOOD_JOBS) + [_POISON_JOB]:
        spec = st["jobs"][job]
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
                {"ResourceType": rt, "Tags": _tags_for(name)} for rt in ("instance", "volume")
            ],
        ),
        # IAM exposes no "this instance profile is usable yet" condition to poll; RunInstances
        # answers InvalidParameterValue until it is, so the bounded retry IS the propagation wait.
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=75,
        delay=2.0,
    )["Instances"][0]["InstanceId"]
    st["instance"] = instance_id
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(_gone_ok(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    info = _poll(
        lambda: _agent_view(ssm, instance_id),
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=_budget_s(ctx, 600),
        interval_s=1,
        what=f"the SSM agent on worker instance {instance_id} coming Online",
        ctx=ctx,
    )
    assert info["PingStatus"] == "Online", f"agent view was {info!r}"


# ===== the refusal ==========================================================
def _assert_poison_refused(ctx, s3, sqs, ssm, st) -> None:
    bucket, queue_url, jobs = st["bucket"], st["queue"], st["jobs"]
    poison = jobs[_POISON_JOB]

    inv = _run_phase(ssm, st["instance"], _worker_script(st["region"], bucket, queue_url, 3),
                     timeout_s=_budget_s(ctx, 900), ctx=ctx)
    assert inv["ResponseCode"] == 0, (
        f"the worker itself failed on the host, so nothing about the poisoned job was measured: "
        f"rc={inv['ResponseCode']!r} stderr={inv['StandardErrorContent'][-600:]!r}"
    )
    report = _json_line(inv)
    assert sorted(report["jobs"]) == sorted(list(_GOOD_JOBS) + [_POISON_JOB]), (
        f"the worker reports handling {sorted(report['jobs'])!r}; the check queued "
        f"{sorted(list(_GOOD_JOBS) + [_POISON_JOB])!r}"
    )

    # Positive control, same worker, same run: the two intact jobs produced the answers the check
    # computed independently.
    for job in _GOOD_JOBS:
        spec, got = jobs[job], report["jobs"][job]
        assert got["errors"] == [], f"the worker reported errors for {job!r}: {got['errors']!r}"
        assert got["writes"] == 1, f"{job!r} must produce exactly one result write; got {got!r}"
        assert got["message_ids"] == [st["sent"][job]], (
            f"the worker processed message ids {got['message_ids']!r} for {job!r}; send_message "
            f"returned {st['sent'][job]!r}"
        )
        body = s3.get_object(Bucket=bucket, Key=spec["result_key"])["Body"].read()
        assert body == spec["expected_body"], (
            f"the result object {spec['result_key']!r} holds {body!r}; the answer the check "
            f"computed independently is {spec['expected_body']!r}"
        )

    # The poisoned job: refused, and refused for the modelled reason.
    bad = report["jobs"][_POISON_JOB]
    assert bad["writes"] == 0, (
        f"the poisoned job must not have written anything; the worker reports {bad!r}"
    )
    assert bad["deletes"] == 0, (
        f"a job the worker could not complete must not be deleted from the queue; the worker "
        f"reports {bad['deletes']!r} deletes for {_POISON_JOB!r}"
    )
    assert bad["errors"], f"the poisoned job reported no error at all: {bad!r}"
    for err in bad["errors"]:
        assert err["stage"] == "get", (
            f"the poisoned job must fail fetching its input, not later; it failed at "
            f"{err['stage']!r}: {err!r}"
        )
        seen = _CLI_ERROR_RE.search(err["stderr"])
        assert seen is not None, (
            f"the guest's stderr carries no AWS error code to grade: {err['stderr']!r}"
        )
        # Without s3:ListBucket, S3 will not disclose whether the key exists and answers 403
        # AccessDenied -- not the 404 NoSuchKey the bucket owner sees for the same key below.
        denied = (
            f"User: arn:aws:sts::{ctx.account}:assumed-role/{st['role']}/{st['instance']} is not "
            f"authorized to perform: s3:ListBucket on resource: \"arn:aws:s3:::{bucket}\" because "
            f"no identity-based policy allows the s3:ListBucket action"
        )
        assert (seen.group(1), seen.group(2).strip()) == ("AccessDenied", denied), (
            f"the guest hit {seen.group(1)!r} fetching the missing input; a principal without "
            f"s3:ListBucket must be refused with AccessDenied {denied!r} rather than told the key "
            f"is absent (stderr={err['stderr']!r})"
        )

    # The same refusal from the check's own client, with a positive control immediately after it.
    missing = _error(lambda: s3.get_object(Bucket=bucket, Key=poison["input_key"]))
    assert missing == ("NoSuchKey", "The specified key does not exist."), (
        f"the missing input key must be refused with NoSuchKey 'The specified key does not "
        f"exist.'; S3 answered {missing!r}"
    )
    control = jobs[_GOOD_JOBS[0]]
    assert (
        s3.get_object(Bucket=bucket, Key=control["input_key"])["Body"].read()
        == control["input"]
    ), (
        "the positive control failed: a key the check did PUT must be readable byte-for-byte, or "
        "the NoSuchKey above says nothing about the missing key"
    )

    # THE EFFECT IS ABSENT: no result object, no version, no delete marker, and results/ holds
    # exactly the two good answers.
    absent = _error(lambda: s3.head_object(Bucket=bucket, Key=poison["result_key"]))
    assert absent == ("404", "Not Found"), (
        f"a partial result object was left behind at {poison['result_key']!r} for a job that "
        f"never completed; HeadObject answered {absent!r}"
    )
    versions = _versions_of(s3, bucket, poison["result_key"])
    assert versions == {"versions": [], "delete_markers": []}, (
        f"{poison['result_key']!r} carries object history {versions!r}; a job that failed before "
        f"writing must have created no version and no delete marker at all"
    )
    results = sorted(_list_keys(s3, bucket, prefix="results/"))
    assert results == sorted(jobs[j]["result_key"] for j in _GOOD_JOBS), (
        f"results/ holds {results!r}; only the two good answers may exist while the poisoned job "
        f"is unsatisfiable"
    )

    # A failed job comes BACK: same message, higher receive count -- and the deleted ones do not.
    # The check's own receive hides it long enough for the repair below to hand it back.
    returned = _poll(
        lambda: sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            VisibilityTimeout=120,
            AttributeNames=["ApproximateReceiveCount"],
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=_budget_s(ctx, 180),
        interval_s=1,
        what=(
            "the poisoned message becoming visible again after its visibility timeout, because a "
            "job nothing deleted must return to the queue"
        ),
        ctx=ctx,
    )
    assert [m["MessageId"] for m in returned] == [st["sent"][_POISON_JOB]], (
        f"the queue returned {[m['MessageId'] for m in returned]!r}; only the poisoned message "
        f"{st['sent'][_POISON_JOB]!r} was left undeleted -- the two the worker deleted must never "
        f"come back"
    )
    body = json.loads(returned[0]["Body"])
    assert body["job"] == _POISON_JOB, f"the returned message body is {body!r}"
    count = int(returned[0]["Attributes"]["ApproximateReceiveCount"])
    assert count >= 2, (
        f"ApproximateReceiveCount on the redelivered poisoned message is {count}; the worker "
        f"already received it once, so a redelivery must report at least 2"
    )
    st["poison_handle"] = returned[0]["ReceiptHandle"]


# ===== recovery once the cause is removed ===================================
def _assert_repair(ctx, s3, sqs, ssm, st) -> None:
    bucket, queue_url = st["bucket"], st["queue"]
    poison = st["jobs"][_POISON_JOB]

    s3.put_object(Bucket=bucket, Key=poison["input_key"], Body=poison["input"])
    # Hand the message straight back rather than waiting out the timeout a second time.
    sqs.change_message_visibility(
        QueueUrl=queue_url, ReceiptHandle=st["poison_handle"], VisibilityTimeout=0
    )

    inv = _run_phase(ssm, st["instance"], _worker_script(st["region"], bucket, queue_url, 1),
                     timeout_s=_budget_s(ctx, 900), ctx=ctx)
    assert inv["ResponseCode"] == 0, (
        f"the repair run failed on the host: rc={inv['ResponseCode']!r} "
        f"stderr={inv['StandardErrorContent'][-600:]!r}"
    )
    report = _json_line(inv)
    assert sorted(report["jobs"]) == [_POISON_JOB], (
        f"the repair run handled {sorted(report['jobs'])!r}; only the once-poisoned job was left "
        f"on the queue"
    )
    got = report["jobs"][_POISON_JOB]
    assert got["errors"] == [], (
        f"the job still failed after its input was created: {got['errors']!r}"
    )
    assert got["writes"] == 1 and got["deletes"] >= 1, (
        f"the repaired job must write its result once and delete its message; the worker reports "
        f"{got!r}"
    )
    assert got["message_ids"] == [st["sent"][_POISON_JOB]], (
        f"the repair run processed {got['message_ids']!r}; the poisoned job's message id is "
        f"{st['sent'][_POISON_JOB]!r}"
    )

    body = s3.get_object(Bucket=bucket, Key=poison["result_key"])["Body"].read()
    assert body == poison["expected_body"], (
        f"the repaired result object holds {body!r}; the answer the check computed independently "
        f"is {poison['expected_body']!r}"
    )
    versions = _versions_of(s3, bucket, poison["result_key"])
    assert len(versions["versions"]) == 1 and versions["delete_markers"] == [], (
        f"the repaired result key must carry exactly one version and no delete marker; it carries "
        f"{versions!r}"
    )
    results = sorted(_list_keys(s3, bucket, prefix="results/"))
    expected = sorted(st["jobs"][j]["result_key"] for j in list(_GOOD_JOBS) + [_POISON_JOB])
    assert results == expected, f"results/ holds {results!r}; expected exactly {expected!r}"

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
        timeout_s=_budget_s(ctx, 300),
        interval_s=1,
        what="the queue draining to zero once every job has succeeded",
        ctx=ctx,
    )
    assert attrs["ApproximateNumberOfMessages"] == "0", attrs
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", attrs
    left = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
    ).get("Messages", [])
    assert left == [], (
        f"a long poll on the drained queue returned {[m.get('MessageId') for m in left]!r}"
    )


# ===== in-band teardown =====================================================
def _teardown(ctx, ec2, s3, sqs, iam, st) -> list:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises naming each one that failed on anything but an already-gone code."""
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
                timeout_s=_budget_s(ctx, 420),
                interval_s=2,
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
            lambda s=sg: _retry_dependency(lambda: ec2.delete_security_group(GroupId=s),
                                           timeout_s=_budget_s(ctx, 240)),
        )
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
            lambda: _retry_dependency(
                lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]),
                timeout_s=_budget_s(ctx, 240),
            ),
        )
    for subnet in st.get("subnets", []):
        _step(
            f"subnet {subnet}",
            lambda s=subnet: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=s),
                                               timeout_s=_budget_s(ctx, 240)),
        )
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
        {"Key": "sim2real", "Value": "sqsjob-poisoned-job-leaves-no-partial-result"},
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
    """Every job's input bytes, salt and the ANSWER, computed here from values the check owns. The
    poisoned job is planned identically -- only its input object is withheld."""
    jobs = {}
    for i, job in enumerate(list(_GOOD_JOBS) + [_POISON_JOB]):
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


def _error(fn):
    """The (code, message) of the ClientError raised by fn. An unexpected SUCCESS raises, so it
    can never be confused with a code mismatch."""
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
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
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
        Description="sim2real sqs poisoned job worker",
        Tags=[{"Key": "sim2real", "Value": "sqsjob-poisoned-job-leaves-no-partial-result"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY))
    )
    # No sqs:SendMessage, no s3:ListBucket, no s3:DeleteObject: the worker can only consume the
    # queue, read what the check PUT under in/ and write under results/. It therefore cannot
    # discover that the poisoned key is missing by any route other than being refused.
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
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="job-scope")))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "sqsjob-poisoned-job-leaves-no-partial-result"}],
    )
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_gone_ok(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        ))
    )


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


def _run_phase(ssm, instance_id, script, timeout_s=900, ctx=None):
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [script]},
            TimeoutSeconds=600,
            Comment="sim2real sqs poisoned job worker",
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


_WORKER = r'''
import json, os, subprocess, sys, time

QUEUE = "__QUEUE__"
BUCKET = "__BUCKET__"
REGION = "__REGION__"
EXPECT = __EXPECT__


def aws(args):
    return subprocess.run(["aws"] + args + ["--region", REGION],
                          capture_output=True, text=True)


def receive():
    """Long poll, with a bounded retry: the instance profile's permissions become usable a moment
    after the host boots, and a transient refusal there is not an empty queue."""
    last = None
    for _ in range(15):
        r = aws(["sqs", "receive-message", "--queue-url", QUEUE,
                 "--max-number-of-messages", "1", "--wait-time-seconds", "20",
                 "--visibility-timeout", "__VISIBILITY__", "--output", "json"])
        if r.returncode == 0:
            out = r.stdout.strip()
            return json.loads(out).get("Messages", []) if out else [], None
        last = r.stderr.strip()[:400]
        time.sleep(2)
    return [], last


report = {"jobs": {}, "polls": 0, "receive_errors": []}
done = {}
empty = 0
deadline = time.time() + 180
# Stop as soon as every expected job has been seen once. One message per receive starts each
# job's visibility clock when the worker takes it, so a finished job is deleted well inside it.
while len(report["jobs"]) < EXPECT and empty < 3 and time.time() < deadline:
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
            # A standard queue may deliver a message more than once; that is legal, so the worker
            # is idempotent and writes NO second result.
            ent["duplicates"] += 1
            d = aws(["sqs", "delete-message", "--queue-url", QUEUE,
                     "--receipt-handle", m["ReceiptHandle"]])
            if d.returncode == 0:
                ent["deletes"] += 1
            continue
        g = aws(["s3api", "get-object", "--bucket", BUCKET, "--key", body["input_key"],
                 "/tmp/in"])
        if g.returncode != 0:
            # The job cannot be completed. Nothing is written and the message is NOT deleted, so
            # it returns to the queue when its visibility timeout expires.
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


def _worker_script(region, bucket, queue_url, expect):
    """The worker, as the SSM command payload; the graded work runs inside the guest."""
    worker = (
        _WORKER.replace("__QUEUE__", queue_url)
        .replace("__BUCKET__", bucket)
        .replace("__REGION__", region)
        .replace("__EXPECT__", str(expect))
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
