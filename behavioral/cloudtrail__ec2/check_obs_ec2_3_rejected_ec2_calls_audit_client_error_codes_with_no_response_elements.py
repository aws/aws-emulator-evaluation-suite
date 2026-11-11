"""obs-ec2-3-rejected-ec2-calls-audit-client-error-codes-with-no-response-elements."""
from __future__ import annotations

import datetime
import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-ec2-3-rejected-ec2-calls-audit-client-error-codes-with-no-response-elements"
GROUP = "error-semantics"
SERVICES = ["cloudtrail", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_AMI_NAME_PATTERN = "al2023-ami-2023.*-kernel-*-x86_64"

# CloudTrail indexes events minutes after the call; bounded inside the 1800 s ec2 ceiling.
_INDEX_BUDGET_S = 900.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# The SDK sees the bare EC2 code, CloudTrail records it with a `Client.` prefix (the fault
# class). The two strings differ, which is why each is asserted separately.
_SDK_NOT_FOUND = "InvalidInstanceID.NotFound"
_AUDIT_NOT_FOUND = "Client.InvalidInstanceID.NotFound"
_SDK_DRY_RUN = "DryRunOperation"
_AUDIT_DRY_RUN = "Client.DryRunOperation"
_NOT_FOUND_MESSAGE = "The instance ID '{instance_id}' does not exist"
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c5",
)
def run(ctx) -> None:
    """Rejected EC2 calls (NotFound, DryRun) are audited with a `Client.`-prefixed errorCode, an
    errorMessage, the SDK request id and no responseElements; a success call has no errorCode.
    """
    ec2 = ctx.client("ec2")
    ct = ctx.client("cloudtrail")
    token = ctx.unique_name("sim2real-xsvc-ctec2n-")
    tag_spec = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real-run", "Value": token}]

    state: dict = {"vpc": None, "subnet": None, "instances": []}
    vpc_id = ec2.create_vpc(
        CidrBlock="10.43.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    state["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _teardown(ec2, state))

    az = _usable_az(ec2, _INSTANCE_TYPE)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.43.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
    )["Subnet"]["SubnetId"]
    state["subnet"] = subnet_id
    image_id = _latest_al2023_ami(ec2)

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()

    # --- (a) DescribeInstances on a well-formed id nobody owns. The SHORT form `i-` + 8 hex
    # deterministically answers InvalidInstanceID.NotFound; random LONG `i-0` + 16 hex ids are often
    # rejected as InvalidInstanceID.Malformed, a validity check the model does not declare.
    unknown_id = "i-" + secrets.token_hex(4)
    nf_code, nf_message, nf_request_id = _expect_client_error(
        lambda: ec2.describe_instances(InstanceIds=[unknown_id]),
        f"DescribeInstances on the nonexistent instance {unknown_id}",
    )
    assert nf_code == _SDK_NOT_FOUND, (
        f"the SDK reported {nf_code!r} for DescribeInstances on unknown id {unknown_id!r}, "
        f"expected {_SDK_NOT_FOUND!r}"
    )
    want_nf_message = _NOT_FOUND_MESSAGE.format(instance_id=unknown_id)
    assert nf_message == want_nf_message, (
        f"DescribeInstances on unknown id {unknown_id!r}: expected message {want_nf_message!r}, "
        f"actual {nf_message!r}"
    )

    # --- (b) A fully valid RunInstances with DryRun=True. If the target LAUNCHES anyway, the
    # instance is recorded in state before anything is asserted so the net terminates it.
    dry_kwargs = dict(
        ImageId=image_id, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tag_spec},
                           {"ResourceType": "volume", "Tags": tag_spec}],
    )
    try:
        launched = ec2.run_instances(DryRun=True, **dry_kwargs)
        state["instances"].extend(i["InstanceId"] for i in launched.get("Instances", []))
        raise AssertionError(
            f"RunInstances with DryRun=True SUCCEEDED and returned "
            f"{[i['InstanceId'] for i in launched.get('Instances', [])]!r}; a dry run must "
            f"answer DryRunOperation and launch nothing"
        )
    except ClientError as err:
        dry_code = err.response["Error"]["Code"]
        dry_message = err.response["Error"].get("Message")
        dry_request_id = err.response["ResponseMetadata"]["RequestId"]
    assert dry_code == _SDK_DRY_RUN, (
        f"the SDK reported {dry_code!r} for a valid DryRun RunInstances, expected {_SDK_DRY_RUN!r}"
    )
    assert dry_message == _DRY_RUN_MESSAGE, (
        f"a valid DryRun RunInstances: expected message {_DRY_RUN_MESSAGE!r}, actual {dry_message!r}"
    )

    # --- Positive control: the same service, same principal, same instant, a call that works.
    ok_resp = ec2.describe_instances(
        Filters=[{"Name": "tag:sim2real-run", "Values": [token]}]
    )
    ok_request_id = ok_resp["ResponseMetadata"]["RequestId"]
    # Effect absent: the DryRun launched nothing carrying this run's unique tag. Scoped to a tag
    # only this run can hold, so "empty" is a property of the query, not of the account.
    leaked = [i["InstanceId"] for r in ok_resp["Reservations"] for i in r["Instances"]]
    state["instances"].extend(leaked)
    assert leaked == [], (
        f"a DryRun RunInstances left instance(s) {leaked!r} tagged sim2real-run={token!r}"
    )
    for rid in (nf_request_id, dry_request_id, ok_request_id):
        assert rid, "an EC2 response carried no ResponseMetadata.RequestId to correlate"
    assert len({nf_request_id, dry_request_id, ok_request_id}) == 3, (
        f"three requests returned non-distinct request ids "
        f"{[nf_request_id, dry_request_id, ok_request_id]!r}"
    )
    _teardown(ec2, state)  # network gone before the long audit wait; the net stays as backstop

    # --- The audit side. DescribeInstances is polled once and both of its records selected.
    found = _await_records(
        ct,
        {"nf": ("DescribeInstances", nf_request_id),
         "ok": ("DescribeInstances", ok_request_id),
         "dry": ("RunInstances", dry_request_id)},
        emitted_at, t0,
    )
    waited = time.monotonic() - t0
    missing = sorted(k for k in ("nf", "ok", "dry") if k not in found)
    assert not missing, (
        f"{DATAPLANE_MARKER}: CloudTrail event history produced no record for {missing!r} after "
        f"{waited:.0f}s (nf={nf_request_id}, dry={dry_request_id}, ok={ok_request_id}). Real AWS "
        f"audits a rejected EC2 call on the same timeline as a successful one."
    )
    _, nf_rec = found["nf"]
    _, dry_rec = found["dry"]
    ok_env, ok_rec = found["ok"]

    # --- (a) the NotFound record.
    assert nf_rec["eventSource"] == "ec2.amazonaws.com", f"eventSource {nf_rec.get('eventSource')!r}"
    assert nf_rec["eventName"] == "DescribeInstances", f"eventName {nf_rec.get('eventName')!r}"
    assert nf_rec["errorCode"] == _AUDIT_NOT_FOUND, (
        f"the audit record for DescribeInstances({unknown_id}) carries errorCode "
        f"{nf_rec.get('errorCode')!r}, expected {_AUDIT_NOT_FOUND!r} -- MEASURED: CloudTrail "
        f"prefixes the fault class; the SDK saw {nf_code!r}"
    )
    assert nf_rec.get("errorMessage") == want_nf_message, (
        f"the NotFound record's errorMessage: expected {want_nf_message!r}, actual "
        f"{nf_rec.get('errorMessage')!r}"
    )
    assert nf_rec.get("responseElements") is None, (
        f"responseElements is {nf_rec.get('responseElements')!r} on a REJECTED DescribeInstances; "
        f"there was no response to record"
    )
    assert nf_rec["requestID"] == nf_request_id, (
        f"record requestID {nf_rec.get('requestID')!r} != SDK request id {nf_request_id!r}"
    )
    assert nf_rec["readOnly"] is True, f"readOnly {nf_rec.get('readOnly')!r} for a Describe"

    # --- (b) the DryRun record.
    assert dry_rec["eventSource"] == "ec2.amazonaws.com", f"eventSource {dry_rec.get('eventSource')!r}"
    assert dry_rec["eventName"] == "RunInstances", f"eventName {dry_rec.get('eventName')!r}"
    assert dry_rec["errorCode"] == _AUDIT_DRY_RUN, (
        f"the audit record for the DryRun RunInstances carries errorCode "
        f"{dry_rec.get('errorCode')!r}, expected {_AUDIT_DRY_RUN!r}; the SDK saw {dry_code!r}"
    )
    assert dry_rec.get("errorMessage") == _DRY_RUN_MESSAGE, (
        f"the DryRun record's errorMessage: expected {_DRY_RUN_MESSAGE!r}, actual "
        f"{dry_rec.get('errorMessage')!r}"
    )
    assert dry_rec.get("responseElements") is None, (
        f"responseElements is {dry_rec.get('responseElements')!r} on a DryRun RunInstances; a "
        f"target that templates the success shape onto a dry run fails here"
    )
    assert dry_rec["requestID"] == dry_request_id, (
        f"record requestID {dry_rec.get('requestID')!r} != SDK request id {dry_request_id!r}"
    )
    assert dry_rec["readOnly"] is False, (
        f"readOnly {dry_rec.get('readOnly')!r}: RunInstances is a write even as a dry run -- the "
        f"classification belongs to the operation, not the outcome"
    )
    # The REQUEST is still recorded on a dry run: it was evaluated in full, then not executed.
    assert dry_rec["requestParameters"]["instanceType"] == _INSTANCE_TYPE, (
        f"DryRun requestParameters.instanceType is "
        f"{(dry_rec.get('requestParameters') or {}).get('instanceType')!r}"
    )

    # --- Positive control: the successful DescribeInstances is audited as a success.
    assert "errorCode" not in ok_rec, (
        f"the SUCCESSFUL DescribeInstances is audited with errorCode {ok_rec.get('errorCode')!r}; "
        f"the rejected records' errorCode is then not evidence of anything"
    )
    assert "errorMessage" not in ok_rec, (
        f"the successful call's record carries errorMessage {ok_rec.get('errorMessage')!r}"
    )
    assert ok_rec["requestID"] == ok_request_id, (
        f"control record requestID {ok_rec.get('requestID')!r} != {ok_request_id!r}"
    )
    assert ok_rec["eventName"] == "DescribeInstances", f"eventName {ok_rec.get('eventName')!r}"
    assert ok_env["EventId"] == ok_rec["eventID"], (
        f"envelope EventId {ok_env['EventId']!r} != record eventID {ok_rec.get('eventID')!r}"
    )


# ===== helpers =====
def _expect_client_error(fn, what: str) -> tuple[str, str, str]:
    """(error code, message, request id). Raises if the call SUCCEEDS -- never a falsy sentinel."""
    try:
        resp = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"]["RequestId"],
        )
    raise AssertionError(f"{what} SUCCEEDED (response {resp!r}); real AWS rejects it")


def _usable_az(ec2, instance_type: str) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[{"Name": "name", "Values": [_AMI_NAME_PATTERN]},
                 {"Name": "architecture", "Values": ["x86_64"]},
                 {"Name": "state", "Values": ["available"]}],
    )["Images"]
    assert images, f"no Amazon-owned available image matches {_AMI_NAME_PATTERN!r}"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _wait_terminated(ec2, instance_id: str, budget_s: float) -> bool:
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        try:
            res = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return True
            raise
        states = [i["State"]["Name"] for r in res for i in r["Instances"]]
        if not states or states == ["terminated"]:
            return True
        time.sleep(2.0)
    return False


def _teardown(ec2, state: dict) -> None:
    """Terminate anything a wrong target launched, then subnet and VPC. Idempotent.

    Anything left behind raises; only the documented not-found codes count as already gone.
    """
    ids = [i for i in state["instances"] if i]
    if ids:
        try:
            ec2.terminate_instances(InstanceIds=ids)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
        for iid in ids:
            if not _wait_terminated(ec2, iid, 240.0):
                raise RuntimeError(f"instance {iid} not terminated")
        state["instances"] = []
    if state["subnet"]:
        _delete_retrying(lambda: ec2.delete_subnet(SubnetId=state["subnet"]),
                         "InvalidSubnetID.NotFound")
        state["subnet"] = None
    if state["vpc"]:
        _delete_retrying(lambda: ec2.delete_vpc(VpcId=state["vpc"]), "InvalidVpcID.NotFound")
        state["vpc"] = None


def _delete_retrying(fn, gone_code: str, budget_s: float = 90.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == gone_code:
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(2.0)


def _lookup_all(ct, **kw) -> list:
    out, nxt = [], None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        for attempt in range(6):
            try:
                resp = ct.lookup_events(**kw)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or attempt == 5:
                    raise
                time.sleep(2.0 * (attempt + 1))
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            break
    return out


def _await_records(ct, wanted: dict, emitted_at, t0: float) -> dict:
    """{key: (envelope, record)} for each {key: (event_name, request_id)}, selected by requestID."""
    found: dict = {}
    window_start = emitted_at - datetime.timedelta(minutes=3)
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        now = datetime.datetime.now(datetime.timezone.utc)
        for name in sorted({n for k, (n, _) in wanted.items() if k not in found}):
            by_rid = {rid: k for k, (n, rid) in wanted.items() if n == name and k not in found}
            for ev in _lookup_all(
                ct, StartTime=window_start, EndTime=now + datetime.timedelta(minutes=5),
                MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
            ):
                rec = json.loads(ev["CloudTrailEvent"])
                key = by_rid.get(rec.get("requestID"))
                if key is not None:
                    found[key] = (ev, rec)
        if len(found) == len(wanted):
            break
        time.sleep(_POLL_INTERVAL_S)
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
