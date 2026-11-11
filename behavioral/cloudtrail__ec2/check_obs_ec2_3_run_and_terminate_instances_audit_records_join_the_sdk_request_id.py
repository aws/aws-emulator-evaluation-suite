"""obs-ec2-3-run-and-terminate-instances-audit-records-join-the-sdk-request-id."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-ec2-3-run-and-terminate-instances-audit-records-join-the-sdk-request-id"
GROUP = "audit-trail"
SERVICES = ["cloudtrail", "ec2"]

# The smallest free-tier-eligible x86_64 type; the instance never needs to boot past `pending`
# for anything asserted here, and it is terminated the moment RunInstances returns.
_INSTANCE_TYPE = "t3.micro"
# Amazon's own AL2023 image, resolved through EC2 itself (no SSM, no hardcoded AMI id).
_AMI_NAME_PATTERN = "al2023-ami-2023.*-kernel-*-x86_64"

# CloudTrail event-history indexing typically takes ~2 minutes; 900 s is a generous ceiling.
_INDEX_BUDGET_S = 900.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40
_TERMINATED_BUDGET_S = 300.0

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c5",
)
def run(ctx) -> None:
    """RunInstances and TerminateInstances each appear in CloudTrail event history as one record
    whose requestID is the SDK's request id, with requestParameters/responseElements matching what
    was requested and what EC2 minted (instance id, subnet, reservation, state).
    """
    ec2 = ctx.client("ec2")
    ct = ctx.client("cloudtrail")
    token = ctx.unique_name("sim2real-xsvc-ctec2-")
    tag_spec = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real-run", "Value": token}]

    state: dict = {"vpc": None, "subnet": None, "instances": []}

    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    state["vpc"] = vpc_id
    # Idempotent, so both this cleanup and the in-body teardown below can run.
    ctx.on_cleanup(lambda: _teardown(ec2, state))

    az = _usable_az(ec2, _INSTANCE_TYPE)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.42.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
    )["Subnet"]["SubnetId"]
    state["subnet"] = subnet_id

    image_id = _latest_al2023_ami(ec2)

    # --- The audited write. Window opens before the call so clock skew cannot hide the record.
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    run_resp = ec2.run_instances(
        ImageId=image_id, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tag_spec},
                           {"ResourceType": "volume", "Tags": tag_spec}],
    )
    instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
    state["instances"].extend(instance_ids)
    assert len(instance_ids) == 1, f"RunInstances MinCount=MaxCount=1 returned {instance_ids!r}"
    instance_id = instance_ids[0]
    run_request_id = run_resp["ResponseMetadata"]["RequestId"]
    assert run_request_id, "RunInstances returned no ResponseMetadata.RequestId to correlate"

    term_resp = ec2.terminate_instances(InstanceIds=[instance_id])
    term_request_id = term_resp["ResponseMetadata"]["RequestId"]
    term_items = term_resp["TerminatingInstances"]
    assert [t["InstanceId"] for t in term_items] == [instance_id], (
        f"TerminateInstances answered for {[t['InstanceId'] for t in term_items]!r}, expected "
        f"exactly [{instance_id!r}]"
    )
    assert term_items[0]["CurrentState"]["Name"] == "shutting-down", (
        f"TerminateInstances reported CurrentState {term_items[0]['CurrentState']!r}, expected "
        f"'shutting-down'"
    )
    sdk_term_state = term_items[0]["CurrentState"]["Name"]
    assert run_request_id != term_request_id, (
        f"RunInstances and TerminateInstances returned the SAME request id {run_request_id!r}; "
        f"each request mints its own"
    )

    # The instance really goes away: the lifecycle's far end, observed, before the audit wait.
    final = _wait_state(ec2, instance_id, "terminated", _TERMINATED_BUDGET_S)
    assert final == "terminated", f"instance {instance_id} settled at {final!r}, not 'terminated'"
    _teardown(ec2, state)  # network gone too, before the long audit wait

    # --- The audit side: poll until both records are indexed, selected by requestID (so the
    # instance-id assertions below are not circular).
    wanted = {"RunInstances": run_request_id, "TerminateInstances": term_request_id}
    found = _await_records(ct, wanted, emitted_at, t0)
    waited = time.monotonic() - t0
    missing = sorted(n for n in wanted if n not in found)
    assert not missing, (
        f"{DATAPLANE_MARKER}: CloudTrail event history never produced a record for {missing!r} "
        f"after {waited:.0f}s (requestIDs {wanted!r}, instance {instance_id}). Real AWS indexes "
        f"an EC2 management event within a few minutes."
    )

    run_env, run_rec = found["RunInstances"]
    term_env, term_rec = found["TerminateInstances"]

    # --- RunInstances: identity of the record.
    assert run_rec["eventSource"] == "ec2.amazonaws.com", (
        f"RunInstances record eventSource is {run_rec.get('eventSource')!r}"
    )
    assert run_rec["eventName"] == "RunInstances", f"eventName is {run_rec.get('eventName')!r}"
    assert run_rec["requestID"] == run_request_id, (
        f"record requestID {run_rec.get('requestID')!r} != SDK request id {run_request_id!r}"
    )
    assert run_rec["awsRegion"] == ctx.region, f"awsRegion is {run_rec.get('awsRegion')!r}"
    assert run_rec["readOnly"] is False, f"readOnly is {run_rec.get('readOnly')!r} for a write"
    assert "errorCode" not in run_rec, (
        f"a SUCCESSFUL RunInstances is audited with errorCode {run_rec.get('errorCode')!r}"
    )
    assert run_env["EventId"] == run_rec["eventID"], (
        f"envelope EventId {run_env['EventId']!r} != record eventID {run_rec.get('eventID')!r}"
    )

    # --- RunInstances: what was REQUESTED is what was recorded.
    req_items = run_rec["requestParameters"]["instancesSet"]["items"]
    assert req_items[0]["imageId"] == image_id, (
        f"requestParameters.instancesSet.items[0].imageId is {req_items[0].get('imageId')!r}, "
        f"but the request asked for {image_id!r}"
    )
    assert run_rec["requestParameters"]["instanceType"] == _INSTANCE_TYPE, (
        f"requestParameters.instanceType is {run_rec['requestParameters'].get('instanceType')!r}"
    )
    rec_tags = {
        t["key"]: t["value"]
        for spec in run_rec["requestParameters"]["tagSpecificationSet"]["items"]
        if spec["resourceType"] == "instance"
        for t in spec["tags"]
    }
    assert rec_tags.get("sim2real-run") == token, (
        f"the instance TagSpecification recorded in requestParameters is {rec_tags!r}; it must "
        f"carry sim2real-run={token!r}, the value this run sent"
    )

    # --- RunInstances: what EC2 MINTED is what was recorded.
    resp_items = run_rec["responseElements"]["instancesSet"]["items"]
    assert [i["instanceId"] for i in resp_items] == [instance_id], (
        f"responseElements.instancesSet.items instance ids are "
        f"{[i.get('instanceId') for i in resp_items]!r}, but RunInstances created {instance_id!r}"
    )
    assert resp_items[0]["subnetId"] == subnet_id, (
        f"responseElements records subnetId {resp_items[0].get('subnetId')!r}, expected {subnet_id!r}"
    )
    assert resp_items[0]["instanceState"]["name"] == "pending", (
        f"responseElements records instanceState {resp_items[0].get('instanceState')!r}; the "
        f"response to RunInstances always reports 'pending'"
    )
    assert run_rec["responseElements"]["reservationId"] == run_resp["ReservationId"], (
        f"responseElements.reservationId {run_rec['responseElements'].get('reservationId')!r} != "
        f"the SDK's ReservationId {run_resp['ReservationId']!r}"
    )
    resources = {(r["ResourceType"], r["ResourceName"]) for r in run_env["Resources"]}
    assert ("AWS::EC2::Instance", instance_id) in resources, (
        f"the LookupEvents envelope Resources {sorted(resources)!r} do not name the instance "
        f"{instance_id!r}"
    )

    # --- TerminateInstances: the second half of the lifecycle, audited separately.
    assert term_rec["eventSource"] == "ec2.amazonaws.com", (
        f"TerminateInstances record eventSource is {term_rec.get('eventSource')!r}"
    )
    assert term_rec["eventName"] == "TerminateInstances", (
        f"eventName is {term_rec.get('eventName')!r}"
    )
    assert term_rec["requestID"] == term_request_id, (
        f"record requestID {term_rec.get('requestID')!r} != SDK request id {term_request_id!r}"
    )
    assert term_env["EventId"] != run_env["EventId"], "two calls share one CloudTrail EventId"
    t_req = term_rec["requestParameters"]["instancesSet"]["items"]
    assert [i["instanceId"] for i in t_req] == [instance_id], (
        f"TerminateInstances requestParameters name {t_req!r}, expected [{instance_id!r}]"
    )
    t_resp = term_rec["responseElements"]["instancesSet"]["items"]
    assert [i["instanceId"] for i in t_resp] == [instance_id], (
        f"TerminateInstances responseElements name {t_resp!r}, expected [{instance_id!r}]"
    )
    assert t_resp[0]["currentState"]["name"] == sdk_term_state == "shutting-down", (
        f"TerminateInstances responseElements currentState is {t_resp[0].get('currentState')!r}, "
        f"but the SDK saw {sdk_term_state!r} in the same response"
    )


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


def _instance_state(ec2, instance_id: str):
    try:
        res = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return None  # eventual consistency right after RunInstances
        raise
    for r in res:
        for inst in r["Instances"]:
            return inst["State"]["Name"]
    return None


def _wait_state(ec2, instance_id: str, want: str, budget_s: float):
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = _instance_state(ec2, instance_id)
        if last == want:
            return last
        time.sleep(2.0)
    return last


def _teardown(ec2, state: dict) -> None:
    """Terminate, wait, then delete subnet and VPC. Idempotent.

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
            if _wait_state(ec2, iid, "terminated", 240.0) not in ("terminated", None):
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
    """A terminated instance's ENI detaches a few seconds after `terminated`; retry only on that."""
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
    """{event_name: (envelope, parsed_record)} for each wanted {event_name: request_id}."""
    found: dict = {}
    window_start = emitted_at - datetime.timedelta(minutes=3)
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        now = datetime.datetime.now(datetime.timezone.utc)
        for name, rid in wanted.items():
            if name in found:
                continue
            for ev in _lookup_all(
                ct, StartTime=window_start, EndTime=now + datetime.timedelta(minutes=5),
                MaxResults=50,
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
            ):
                rec = json.loads(ev["CloudTrailEvent"])
                if rec.get("requestID") == rid:
                    found[name] = (ev, rec)
                    break
        if len(found) == len(wanted):
            break
        time.sleep(_POLL_INTERVAL_S)
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
