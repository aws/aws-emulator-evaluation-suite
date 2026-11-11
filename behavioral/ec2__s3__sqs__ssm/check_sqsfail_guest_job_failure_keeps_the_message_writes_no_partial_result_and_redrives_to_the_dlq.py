"""sqsfail-guest-job-failure-keeps-the-message-writes-no-partial-result-and-redrives-to-the-dlq."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "sqsfail-guest-job-failure-keeps-the-message-writes-no-partial-result-and-redrives-to-the-dlq"
)
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

_VPC_CIDR = "10.83.0.0/16"
_SUBNET_CIDR = "10.83.7.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")

#: Sized to fit every observation made while the message is invisible, with margin; a tighter
#: window risks an observing receive landing after expiry and spending a delivery.
_VISIBILITY_S = 60
_MAX_RECEIVE = 2
#: 262144 records of 4 bytes = 1 MiB. The reduction over 0..n-1 has a closed form, so the expected
#: answer is computed arithmetically, never by running the guest's algorithm.
_RECORDS = 262144
#: The poison object is short by exactly this many records, so the guest's reduction completes over
#: the bytes that ARE there and only the record-count validation fails -- a failure mid-job, after
#: the input was consumed, which is the only kind that could plausibly leave a partial result.
_SHORT_BY = 3


# timing:real-time — visibility: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An EC2 worker that fails an SQS job leaves the message to reappear with receive count 2, then
    be redriven intact to the DLQ, with no result in S3; a good job writes the predicted bytes.
    """
    # Teardown runs in a `finally` because instance and ENI waits exceed the cleanup time budget.
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "queues": [], "rt": [], "time_left": ctx.time_left}
    try:
        _build(ctx, ec2, s3, sqs, ssm, iam, st)
        _assert_failure_path(s3, sqs, ssm, st)
        _assert_positive_control(s3, sqs, ssm, st)
    finally:
        _teardown(ec2, s3, sqs, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, s3, sqs, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-sqsf-")
    st["name"], st["region"] = name, region
    st["account"] = ctx.client("sts").get_caller_identity()["Account"]

    zone = _usable_zone(ec2)
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(_tolerate_gone(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name + "-subnet")}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(_tolerate_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(name + "-igw")}]
    )["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw_id
    ctx.on_cleanup(_tolerate_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        _tolerate_gone(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        )
    )

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(name + "-rt")}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_tolerate_gone(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    st["rt"].append((rt_id, assoc))
    ctx.on_cleanup(_tolerate_gone(lambda: ec2.disassociate_route_table(AssociationId=assoc)))

    sg = ec2.create_security_group(
        GroupName=name + "-worker",
        Description="sim2real sqs failure-path worker host",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name + "-worker")}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(_tolerate_gone(lambda: ec2.delete_security_group(GroupId=sg)))

    bucket = name + "-bkt"
    st["bucket"] = bucket
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(_tolerate_gone(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})

    dlq_url = sqs.create_queue(
        QueueName=name + "-dlq", tags={"sim2real": "sqsfail-failure-path"}
    )["QueueUrl"]
    st["queues"].append(dlq_url)
    ctx.on_cleanup(_tolerate_gone(lambda: sqs.delete_queue(QueueUrl=dlq_url)))
    dlq_arn = _queue_arn(sqs, dlq_url)
    src_url = sqs.create_queue(
        QueueName=name + "-jobs",
        Attributes={
            "VisibilityTimeout": str(_VISIBILITY_S),
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": str(_MAX_RECEIVE)}
            ),
        },
        tags={"sim2real": "sqsfail-failure-path"},
    )["QueueUrl"]
    st["queues"].append(src_url)
    ctx.on_cleanup(_tolerate_gone(lambda: sqs.delete_queue(QueueUrl=src_url)))
    st["dlq_url"], st["src_url"] = dlq_url, src_url
    st["src_arn"] = _queue_arn(sqs, src_url)

    # The two inputs. `good` is whole; `poison` is short by _SHORT_BY records, so the guest's
    # reduction runs to completion and only the declared-record-count check fails.
    st["good_bytes"] = _input_bytes(_RECORDS)
    st["poison_bytes"] = _input_bytes(_RECORDS)[: 4 * (_RECORDS - _SHORT_BY)]
    s3.put_object(Bucket=bucket, Key="inputs/good.bin", Body=st["good_bytes"])
    s3.put_object(Bucket=bucket, Key="inputs/poison.bin", Body=st["poison_bytes"])

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name, bucket, st["src_arn"])

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
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=30,
        delay=5.0,
    )["Instances"][0]["InstanceId"]
    st["instance"] = instance_id
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    info = _poll(
        lambda: _agent_view(ssm, instance_id),
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=600,
        interval_s=10,
        what=f"the SSM agent on worker instance {instance_id} coming Online",
    )
    assert info["PingStatus"] == "Online", f"agent view was {info!r}"


# ===== the claim: the failure path ==========================================
def _assert_failure_path(s3, sqs, ssm, st) -> None:
    bucket, src_url, dlq_url = st["bucket"], st["src_url"], st["dlq_url"]
    body = _job_body(bucket, "poison")
    st["poison_body"] = body
    sent = sqs.send_message(
        QueueUrl=src_url,
        MessageBody=body,
        MessageAttributes={"jobId": {"DataType": "String", "StringValue": "poison"}},
    )
    st["poison_sent"] = sent
    assert sent["MD5OfMessageBody"] == hashlib.md5(body.encode()).hexdigest(), (
        f"SQS acknowledged the job body with MD5OfMessageBody {sent['MD5OfMessageBody']!r}; the "
        f"MD5 of the bytes sent is {hashlib.md5(body.encode()).hexdigest()!r}"
    )

    # --- receive 1: the worker fails and keeps the message --------------------
    first = _json_line(_run_worker(ssm, st, deadline_s=90, expect_rc=3))
    _assert_worker_failed(first, st, want_count="1", attempt=1)

    # The message is IN FLIGHT: a receive returns nothing, and keeps returning nothing, while the
    # queue reports exactly one message not visible. Two independent observables, because
    # ApproximateNumberOfMessagesNotVisible is documented as approximate and the empty receive is not.
    held = _holds_for(
        lambda: _peek(sqs, src_url),
        lambda got: got == 0,
        seconds=9,
        interval_s=3,
        what="the failed job's message staying invisible for the visibility timeout",
    )
    assert held == 0, f"a receive returned {held!r} messages while the message should be in flight"
    counts = _poll(
        lambda: _queue_counts(sqs, src_url),
        lambda c: c == ("0", "1"),
        timeout_s=30,
        interval_s=3,
        what="the queue reporting the failed job's message as in flight (visible 0, not visible 1)",
    )
    assert counts == ("0", "1"), (
        f"the worker failed without deleting, so exactly one message must be in flight; the queue "
        f"reports (visible, not visible) = {counts!r}"
    )
    _assert_no_result(s3, bucket, "after the first failed attempt")

    # --- the message becomes visible again, with the count incremented -------
    _await_visible_again(sqs, src_url, first, "the first failed delivery", st["time_left"])
    second = _json_line(_run_worker(ssm, st, deadline_s=90, expect_rc=3))
    _assert_worker_failed(second, st, want_count="2", attempt=2)
    assert second["message_id"] == first["message_id"], (
        f"the redelivered message must be the SAME message: attempt 1 saw "
        f"{first['message_id']!r}, attempt 2 saw {second['message_id']!r}"
    )
    assert second["sent_timestamp"] == first["sent_timestamp"], (
        f"redelivery must not re-enqueue: SentTimestamp was {first['sent_timestamp']!r} and is now "
        f"{second['sent_timestamp']!r}"
    )
    assert second["receipt_handle_sha256"] != first["receipt_handle_sha256"], (
        "each delivery of a message carries its own receipt handle; both attempts got the same one"
    )
    _assert_no_result(s3, bucket, "after the second failed attempt")

    # --- receive 3 is EMPTY: the redrive policy has moved the message --------
    # SQS evaluates the redrive policy only on a receive started after the visibility timeout
    # expires (a long poll already in flight does not trigger it), so the third attempt is
    # sequenced on the delivery timestamp the guest reported.
    _await_visible_again(sqs, src_url, second, "the second failed delivery", st["time_left"])
    third = _json_line(_run_worker(ssm, st, deadline_s=60, expect_rc=0))
    assert third["received"] == 0, (
        f"after {_MAX_RECEIVE} failed deliveries the source queue must hand the worker nothing; it "
        f"received {third!r}"
    )
    # Waited out on the DLQ's counters, not by receiving: the carried-over receive count is a claim,
    # so the first read of this message must be the first read of it.
    try:
        _poll(
            lambda: _queue_counts(sqs, dlq_url),
            lambda c: c == ("1", "0"),
            timeout_s=240,
            interval_s=5,
            what="the failed job's message arriving in the dead-letter queue",
        )
    except AssertionError as exc:
        raise AssertionError(
            f"{exc}; at that point the source queue's RedrivePolicy was "
            f"{_queue_attr(sqs, src_url, 'RedrivePolicy')!r} and its (visible, not visible) counts "
            f"were {_queue_counts(sqs, src_url)!r}"
        ) from exc
    dead = _receive_one(sqs, dlq_url, "the dead-letter queue")
    st["dead_id"] = dead["MessageId"]
    assert dead["Body"] == body, (
        f"the DLQ must carry the ORIGINAL body byte-for-byte; it carries {dead['Body']!r}, the job "
        f"was sent as {body!r}"
    )
    assert dead["MD5OfBody"] == sent["MD5OfMessageBody"], (
        f"the DLQ copy's MD5OfBody is {dead['MD5OfBody']!r}, the send acknowledged "
        f"{sent['MD5OfMessageBody']!r}"
    )
    assert dead["MessageId"] == sent["MessageId"], (
        f"a redriven message keeps its message id; sent {sent['MessageId']!r}, DLQ holds "
        f"{dead['MessageId']!r}"
    )
    assert dead["Attributes"]["SentTimestamp"] == first["sent_timestamp"], (
        f"the redrive must preserve the original enqueue timestamp: the worker saw "
        f"{first['sent_timestamp']!r}, the DLQ copy reports "
        f"{dead['Attributes']['SentTimestamp']!r}"
    )
    assert dead["Attributes"]["ApproximateFirstReceiveTimestamp"] == first["first_receive"], (
        f"the redrive must preserve ApproximateFirstReceiveTimestamp: the worker saw "
        f"{first['first_receive']!r}, the DLQ copy reports "
        f"{dead['Attributes']['ApproximateFirstReceiveTimestamp']!r}"
    )
    assert dead["Attributes"]["ApproximateReceiveCount"] == str(_MAX_RECEIVE + 1), (
        f"the receive count carries across the move and counts this read, so after "
        f"{_MAX_RECEIVE} deliveries on the source queue the first DLQ read must report "
        f"{_MAX_RECEIVE + 1}; it reports "
        f"{dead['Attributes']['ApproximateReceiveCount']!r}"
    )
    assert dead["Attributes"].get("DeadLetterQueueSourceArn") == st["src_arn"], (
        f"the DLQ copy must name the queue it was redriven FROM, which is what distinguishes a "
        f"redrive from a send; it names {dead['Attributes'].get('DeadLetterQueueSourceArn')!r}, the "
        f"source queue is {st['src_arn']!r}"
    )
    assert dead.get("MessageAttributes") == {
        "jobId": {"StringValue": "poison", "DataType": "String"}
    }, (
        f"the redrive must preserve the message attributes; the DLQ copy carries "
        f"{dead.get('MessageAttributes')!r}"
    )
    src_counts = _poll(
        lambda: _queue_counts(sqs, src_url),
        lambda c: c == ("0", "0"),
        timeout_s=120,
        interval_s=5,
        what="the source queue emptying once the message was redriven",
    )
    assert src_counts == ("0", "0"), (
        f"the redriven message must be gone from the source queue; it reports {src_counts!r}"
    )
    _assert_no_result(s3, bucket, "after the message was redriven to the DLQ")


# ===== the claim: the positive control ======================================
def _assert_positive_control(s3, sqs, ssm, st) -> None:
    bucket, src_url, dlq_url = st["bucket"], st["src_url"], st["dlq_url"]
    want_line = _expected_result(st["good_bytes"], _RECORDS)
    body = _job_body(bucket, "good")
    sent = sqs.send_message(
        QueueUrl=src_url,
        MessageBody=body,
        MessageAttributes={"jobId": {"DataType": "String", "StringValue": "good"}},
    )

    done = _json_line(_run_worker(ssm, st, deadline_s=120, expect_rc=0))
    assert done["received"] == 1 and done["job"] == "good", (
        f"the worker must have been handed the completable job; it reports {done!r}"
    )
    assert done["message_id"] == sent["MessageId"], (
        f"the worker received {done['message_id']!r}, the runner sent {sent['MessageId']!r}"
    )
    assert done["receive_count"] == "1", (
        f"the completable job is delivered once; the worker reports receive count "
        f"{done['receive_count']!r}"
    )
    assert done["status"] == "ok" and done["uploaded"] is True and done["deleted"] is True, (
        f"the worker must have uploaded its result and then deleted its own message; it reports "
        f"{done!r}"
    )
    assert done["input_sha256"] == hashlib.sha256(st["good_bytes"]).hexdigest(), (
        f"the guest reduced {done['input_sha256']!r}; the runner uploaded "
        f"{hashlib.sha256(st['good_bytes']).hexdigest()!r}"
    )
    # Predicted arithmetically from the generated input, never by re-running the guest's algorithm.
    assert (done["count"], done["total"], done["max"]) == (
        _RECORDS,
        _RECORDS * (_RECORDS - 1) // 2,
        _RECORDS - 1,
    ), (
        f"the guest reduced the {_RECORDS} records to {(done['count'], done['total'], done['max'])!r}; "
        f"the closed form over 0..{_RECORDS - 1} is "
        f"{(_RECORDS, _RECORDS * (_RECORDS - 1) // 2, _RECORDS - 1)!r}"
    )

    stored = s3.get_object(Bucket=bucket, Key="results/good.txt")["Body"].read()
    assert stored == want_line, (
        f"the stored result object must be the predicted bytes exactly; S3 holds {stored!r}, the "
        f"runner predicted {want_line!r}"
    )
    head = s3.head_object(Bucket=bucket, Key="results/good.txt")
    assert head["ETag"].strip('"') == hashlib.md5(want_line).hexdigest(), (
        f"S3's ETag for the result is {head['ETag']!r}, the MD5 of the predicted bytes is "
        f"{hashlib.md5(want_line).hexdigest()!r}"
    )
    assert head["ContentLength"] == len(want_line), (
        f"the result object is {head['ContentLength']!r} bytes, the predicted result is "
        f"{len(want_line)!r}"
    )
    # The failed job's result is STILL absent, and it is the only other key results/ could hold.
    listed = _list_keys(s3, bucket, prefix="results/")
    assert listed == ["results/good.txt"], (
        f"results/ must hold exactly the completed job's object; it holds {listed!r}"
    )
    gone = _error_code(lambda: s3.head_object(Bucket=bucket, Key="results/poison.txt"))
    assert gone == "404", (
        f"the failed job must have left no result object; HeadObject on results/poison.txt returned "
        f"{gone!r}"
    )

    # The completed job deleted its own message, so the source queue stays empty and the DLQ, proven
    # to work by the poison message, keeps holding exactly that one message.
    _poll(
        lambda: _queue_counts(sqs, src_url),
        lambda c: c == ("0", "0"),
        timeout_s=120,
        interval_s=5,
        what="the source queue emptying after the worker deleted its own message",
    )
    held = _holds_for(
        lambda: _queue_counts(sqs, dlq_url),
        lambda c: c == ("1", "0"),
        seconds=30,
        interval_s=10,
        what="the DLQ depth staying at the one failed job while the completed job stays out of it",
    )
    assert held == ("1", "0"), (
        f"the completed job must never reach the DLQ, so its depth must stay at the one redriven "
        f"message; the DLQ reports (visible, not visible) = {held!r}"
    )
    still = _receive_one(sqs, dlq_url, "the dead-letter queue after the completed job")
    assert still["MessageId"] == st["dead_id"], (
        f"the one message in the DLQ must still be the failed job {st['dead_id']!r}; it is "
        f"{still['MessageId']!r}"
    )
    # Converged, then held: Approximate* counters are sampled across servers, so one read is not
    # proof of "empty" and can flip back after a (0, 0) poll; the claim is about a window.
    src_counts = _poll(
        lambda: _queue_counts(sqs, src_url),
        lambda c: c == ("0", "0"),
        timeout_s=90,
        interval_s=5,
        what="the source queue reading empty after the completed job",
    )
    src_counts = _holds_for(
        lambda: _queue_counts(sqs, src_url),
        lambda c: c == ("0", "0"),
        seconds=20,
        interval_s=5,
        what="the source queue STAYING empty -- the deleted message is never redelivered",
    )
    assert src_counts == ("0", "0"), (
        f"the source queue must be empty after the completed job; it reports {src_counts!r}"
    )


def _assert_worker_failed(report, st, want_count, attempt) -> None:
    body = st["poison_body"]
    assert report["received"] == 1 and report["job"] == "poison", (
        f"attempt {attempt}: the worker must have been handed the poison job; it reports {report!r}"
    )
    assert report["message_id"] == st["poison_sent"]["MessageId"], (
        f"attempt {attempt}: the worker received {report['message_id']!r}, the runner sent "
        f"{st['poison_sent']['MessageId']!r}"
    )
    assert report["body_sha256"] == hashlib.sha256(body.encode()).hexdigest(), (
        f"attempt {attempt}: the body the worker read hashes to {report['body_sha256']!r}, the "
        f"runner sent bytes hashing to {hashlib.sha256(body.encode()).hexdigest()!r}"
    )
    assert report["receive_count"] == want_count, (
        f"attempt {attempt}: ApproximateReceiveCount must be {want_count!r}; the worker saw "
        f"{report['receive_count']!r}"
    )
    assert report["status"] == "compute-failed", (
        f"attempt {attempt}: the job must have failed on the host; it reports {report!r}"
    )
    assert report["actual_records"] == _RECORDS - _SHORT_BY, (
        f"attempt {attempt}: the guest found {report['actual_records']!r} records in the truncated "
        f"input; the runner uploaded {_RECORDS - _SHORT_BY}"
    )
    assert report["declared_records"] == _RECORDS, (
        f"attempt {attempt}: the job declared {report['declared_records']!r} records"
    )
    assert report["uploaded"] is False and report["deleted"] is False, (
        f"attempt {attempt}: a failed job must neither upload a result nor delete its message; the "
        f"worker reports {report!r}"
    )


def _assert_no_result(s3, bucket, when) -> None:
    """No result object, no truncated object, no in-progress multipart upload -- anywhere."""
    listed = _list_keys(s3, bucket, prefix="results/")
    assert listed == [], f"{when}: results/ must be empty; it holds {listed!r}"
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key="results/poison.txt"))
    assert code == "404", (
        f"{when}: HeadObject on the failed job's result key must be a 404; it returned {code!r}"
    )
    parts = s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])
    assert parts == [], (
        f"{when}: a partial result could also survive as an in-progress multipart upload; the "
        f"bucket has {parts!r}"
    )
    everything = _list_keys(s3, bucket)
    assert everything == ["inputs/good.bin", "inputs/poison.bin"], (
        f"{when}: the bucket must hold only the two inputs the runner uploaded; it holds "
        f"{everything!r}"
    )


# ===== in-band teardown =====================================================
def _teardown(ec2, s3, sqs, iam, st) -> list:
    """Ordered teardown with the waits the cleanup time budget cannot afford. Runs every step,
    then raises naming each one that failed on anything but an already-gone code."""
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
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    if st.get("igw"):
        _step(
            "igw-detach",
            lambda: _retry_dependency(
                lambda: ec2.detach_internet_gateway(InternetGatewayId=st["igw"], VpcId=st["vpc"])
            ),
        )
        _step(
            "igw",
            lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]),
        )
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(lambda: ec2.delete_security_group(GroupId=s)))
    for rt_id, assoc in st.get("rt", []):
        _step(f"rt-assoc {assoc}", lambda a=assoc: ec2.disassociate_route_table(AssociationId=a))
        _step(f"rt {rt_id}", lambda r=rt_id: _retry_dependency(lambda: ec2.delete_route_table(RouteTableId=r)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=s)))
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


def _tags_for(name):
    return [
        {"Key": "Name", "Value": name},
        {"Key": "sim2real", "Value": "sqsfail-failure-path"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _input_bytes(records):
    """`records` big-endian uint32 holding 0..records-1, so count/sum/max have a closed form."""
    return struct.pack(">%dI" % records, *range(records))


def _expected_result(source, records):
    """The exact bytes the worker must store: the closed form, plus the sha256 of what was uploaded."""
    line = "%d %d %d %s\n" % (
        records,
        records * (records - 1) // 2,
        records - 1,
        hashlib.sha256(source).hexdigest(),
    )
    return line.encode()


def _job_body(bucket, job):
    """Canonical JSON, so the byte-for-byte DLQ comparison is over bytes the check controls."""
    return json.dumps(
        {
            "bucket": bucket,
            "in": f"inputs/{job}.bin",
            "job": job,
            "out": f"results/{job}.txt",
            "records": _RECORDS,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _error_code(fn):
    """The ClientError code raised by fn; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be refused but it succeeded")


def _tolerate_gone(fn):
    """Wrap a `ctx.on_cleanup` delete so it is a no-op if `_teardown` already removed the resource.

    The runner always runs every registered cleanup (`Context.run_cleanups`), on top of this
    check's own in-band `_teardown`, so the second delete routinely lands on a gone resource; only
    an unexpected code is still a real cleanup failure."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise

    return run


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
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _queue_arn(sqs, url):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _queue_attr(sqs, url, name):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[name])["Attributes"].get(name)


def _await_visible_again(sqs, url, report, which, time_left):
    """Wait out the visibility timeout `report`'s delivery started, then prove the message is back.

    Timed from the guest's own receive stamp and polled on queue counts, which spend no delivery."""
    received_at = int(report["received_at_ms"]) / 1000.0
    wake = received_at + _VISIBILITY_S + 5
    slack = wake - time.time()
    assert slack > 0, (
        f"{which}: the runner's own observations overran the {_VISIBILITY_S}s visibility window by "
        f"{-slack:.1f}s, so the message may already have been redelivered outside this check's "
        f"control; raise _VISIBILITY_S"
    )
    budget_s = slack + 90
    left = time_left()
    if left is not None:
        budget_s = min(budget_s, max(0.0, left - 10.0))
    counts = _poll(
        lambda: _queue_counts(sqs, url),
        lambda c: c == ("1", "0"),
        timeout_s=budget_s,
        interval_s=2,
        what=(
            f"the message becoming visible again after {which} (the {_VISIBILITY_S}s visibility "
            f"timeout elapsed at {wake - 5:.0f})"
        ),
    )
    assert counts == ("1", "0"), (
        f"{which}: once the visibility timeout elapses the undeleted message must be visible again; "
        f"the queue reports (visible, not visible) = {counts!r}"
    )


def _queue_counts(sqs, url):
    a = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return a["ApproximateNumberOfMessages"], a["ApproximateNumberOfMessagesNotVisible"]


def _peek(sqs, url):
    """How many messages a receive returns right now."""
    return len(
        sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1).get(
            "Messages", []
        )
    )


def _receive_one(sqs, url, which, attempts=6):
    """Read exactly one message, without deleting it and without counting an empty poll as a miss.

    MaxNumberOfMessages stays 1: with VisibilityTimeout=0 a batch receive can return the same message
    repeatedly in one response."""
    for _ in range(attempts):
        got = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=5,
            VisibilityTimeout=0,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
        ).get("Messages", [])
        if got:
            assert len(got) == 1, f"{which}: asked for one message and got {len(got)}"
            return got[0]
    raise AssertionError(
        f"{which}: {attempts} long polls returned nothing, though GetQueueAttributes reported a "
        f"visible message"
    )


def _vpc_enis(ec2, vpc_id):
    return [
        e["NetworkInterfaceId"]
        for e in ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["NetworkInterfaces"]
    ]


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for up in page.get("Uploads", []):
            s3.abort_multipart_upload(Bucket=bucket, Key=up["Key"], UploadId=up["UploadId"])
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
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return sorted(keys)


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
        Description="sim2real sqs failure-path worker",
        Tags=[{"Key": "sim2real", "Value": "sqsfail-failure-path"}],
    )
    ctx.on_cleanup(_tolerate_gone(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(
        _tolerate_gone(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
        )
    )
    # Scoped so the DLQ's contents cannot be the job's doing: receive/delete on the SOURCE queue
    # only, no sqs:SendMessage anywhere, no s3:DeleteObject, and write access confined to results/.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="worker-scope",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage"],
                        "Resource": queue_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/inputs/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/results/*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _tolerate_gone(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="worker-scope")
        )
    )
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "sqsfail-failure-path"}],
    )
    ctx.on_cleanup(
        _tolerate_gone(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    )
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        _tolerate_gone(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=role_name, RoleName=role_name
            )
        )
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
        time.sleep(10)
    raise AssertionError(f"instance {instance_id} never reached terminated within {timeout_s}s")


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_worker(ssm, st, deadline_s, expect_rc, timeout_s=600):
    """One worker pass on the guest: receive, compute, and on success upload then delete."""
    script = _worker_script(st["region"], st["src_url"], deadline_s)
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[st["instance"]],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [script]},
            TimeoutSeconds=600,
            Comment="sim2real sqs failure-path worker",
        ),
        codes=_THROTTLE + ("InvalidInstanceId",),
        retries=12,
        delay=10.0,
    )
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=st["instance"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(
        _inv,
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=timeout_s,
        interval_s=2.0,
        what=f"invocation {command_id} reaching a terminal status",
    )
    assert inv["ResponseCode"] == expect_rc, (
        f"the worker pass exited {inv['ResponseCode']!r}, expected {expect_rc!r}; "
        f"stdout={inv['StandardOutputContent'][-400:]!r} "
        f"stderr={inv['StandardErrorContent'][-600:]!r}"
    )
    return inv


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return json.loads(lines[-1])


_WORKER_TEMPLATE = """set -uo pipefail
export AWS_DEFAULT_REGION=__REGION__
Q='__QUEUE__'
rm -f /tmp/msg.json /tmp/recv.json /tmp/final.json /tmp/out.txt /tmp/in.bin /tmp/env.sh \
      /tmp/parsed.json /tmp/handle.txt
cat > /tmp/reduce.py <<'PYEOF'
import hashlib, json, struct
meta = json.load(open("/tmp/parsed.json"))
data = open("/tmp/in.bin", "rb").read()
declared = int(meta["declared_records"])
actual_records = len(data) // 4
total = 0
biggest = -1
if len(data) % 4 == 0 and actual_records:
    vals = struct.unpack(">%dI" % actual_records, data)
    total = sum(vals)
    biggest = max(vals)
meta.update({"actual_bytes": len(data), "actual_records": actual_records,
             "input_sha256": hashlib.sha256(data).hexdigest(),
             "uploaded": False, "deleted": False})
if len(data) % 4 or actual_records != declared:
    meta.update({"status": "compute-failed", "reason": "input-record-count-mismatch"})
    json.dump(meta, open("/tmp/final.json", "w"))
    raise SystemExit(3)
line = "%d %d %d %s\\n" % (actual_records, total, biggest, meta["input_sha256"])
with open("/tmp/out.txt", "w") as fh:
    fh.write(line)
meta.update({"status": "computed", "count": actual_records, "total": total, "max": biggest,
             "result_line": line})
json.dump(meta, open("/tmp/final.json", "w"))
PYEOF
DEADLINE=$(( $(date +%s) + __DEADLINE__ ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  if ! aws sqs receive-message --queue-url "$Q" --max-number-of-messages 1 \
      --wait-time-seconds 20 --attribute-names All --message-attribute-names All \
      > /tmp/recv.json 2>/tmp/recv.err; then
    cat /tmp/recv.err >&2
    echo '{"received": -1, "stage": "receive"}'
    exit 4
  fi
  if [ -s /tmp/recv.json ]; then
    cp /tmp/recv.json /tmp/msg.json
    break
  fi
done
if [ ! -f /tmp/msg.json ]; then
  echo '{"received": 0}'
  exit 0
fi
python3 - <<'PYEOF'
import hashlib, json, time
m = json.load(open("/tmp/msg.json"))["Messages"][0]
body = m["Body"]
job = json.loads(body)
open("/tmp/handle.txt", "w").write(m["ReceiptHandle"])
with open("/tmp/env.sh", "w") as fh:
    fh.write("BUCKET=%s\\nINKEY=%s\\nOUTKEY=%s\\n" % (job["bucket"], job["in"], job["out"]))
json.dump({"received": 1, "job": job["job"], "message_id": m["MessageId"],
           # Stamped by the guest right after its own ReceiveMessage returned: the instant the
           # visibility timeout started running. A hair late, never early, so the runner's wait
           # derived from it can only be too long.
           "received_at_ms": int(time.time() * 1000),
           "receive_count": m["Attributes"]["ApproximateReceiveCount"],
           "sent_timestamp": m["Attributes"]["SentTimestamp"],
           "first_receive": m["Attributes"]["ApproximateFirstReceiveTimestamp"],
           "md5_of_body": m["MD5OfBody"],
           "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
           "receipt_handle_sha256": hashlib.sha256(m["ReceiptHandle"].encode()).hexdigest(),
           "declared_records": job["records"]},
          open("/tmp/parsed.json", "w"))
PYEOF
. /tmp/env.sh
if ! aws s3api get-object --bucket "$BUCKET" --key "$INKEY" /tmp/in.bin \
    >/dev/null 2>/tmp/get.err; then
  cat /tmp/get.err >&2
  echo '{"received": 1, "stage": "get-object"}'
  exit 5
fi
python3 /tmp/reduce.py
RC=$?
if [ "$RC" != "0" ]; then
  cat /tmp/final.json
  exit "$RC"
fi
if ! aws s3api put-object --bucket "$BUCKET" --key "$OUTKEY" --body /tmp/out.txt \
    >/dev/null 2>/tmp/put.err; then
  cat /tmp/put.err >&2
  cat /tmp/final.json
  exit 6
fi
if ! aws sqs delete-message --queue-url "$Q" \
    --receipt-handle "$(cat /tmp/handle.txt)" 2>/tmp/del.err; then
  cat /tmp/del.err >&2
  cat /tmp/final.json
  exit 7
fi
python3 - <<'PYEOF'
import json
d = json.load(open("/tmp/final.json"))
d.update({"uploaded": True, "deleted": True, "status": "ok"})
json.dump(d, open("/tmp/final.json", "w"))
PYEOF
cat /tmp/final.json
"""


def _worker_script(region, queue_url, deadline_s):
    return (
        _WORKER_TEMPLATE.replace("__REGION__", region)
        .replace("__QUEUE__", queue_url)
        .replace("__DEADLINE__", str(deadline_s))
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
