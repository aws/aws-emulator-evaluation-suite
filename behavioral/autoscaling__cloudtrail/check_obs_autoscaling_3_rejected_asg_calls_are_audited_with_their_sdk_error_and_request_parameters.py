"""obs-autoscaling-3-rejected-asg-calls-are-audited-with-their-sdk-error-and-request-parameters."""
from __future__ import annotations

import datetime
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-autoscaling-3-rejected-asg-calls-are-audited-with-their-sdk-error-and-request-parameters"
GROUP = "error-semantics"
SERVICES = ["autoscaling", "cloudtrail"]

# Marks a missing audit record as a fidelity failure rather than an unimplemented feature.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# CloudTrail indexing delay: AWS typically shows all three records within about a minute. This is
# a ceiling, not a wait; the poll returns as soon as every record is seen.
_INDEX_CEILING_S = 1200.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# The SDK sees the awsQuery wire code (AlreadyExists, ValidationError) while CloudTrail records
# the exception name (AlreadyExistsFault, ValidationException); the messages are identical.
_DUP_SDK_CODE = "AlreadyExists"
_DUP_AUDIT_CODE = "AlreadyExistsFault"
_BOUNDS_SDK_CODE = "ValidationError"
_BOUNDS_AUDIT_CODE = "ValidationException"
_BOUNDS_SDK_MESSAGE = "Max bound, 1, must be greater than or equal to min bound, 3"

_INSTANCE_TYPE = "t3.micro"
_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A successful CreateAutoScalingGroup and two rejected calls each reach CloudTrail with the
    SDK's requestID, the parameters actually sent and, for rejections only, the matching errorCode
    and the SDK's exact errorMessage; the rejected calls leave the group unchanged.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/logging-using-cloudtrail.html
    """
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ct = ctx.client("cloudtrail")

    az = _usable_az(ec2, _INSTANCE_TYPE, ctx=ctx)
    subnet = _network_zone_subnets(ctx, [az])
    ami = ssm.get_parameter(Name=_AMI_PARAMETER)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"public SSM parameter {_AMI_PARAMETER!r} resolved to {ami!r}"

    lt_name = ctx.unique_name("sim2real-xsvc-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": _INSTANCE_TYPE},
        TagSpecifications=[{"ResourceType": "launch-template",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    name = ctx.unique_name("sim2real-xsvc-asg-")
    lt_ref = {"LaunchTemplateName": lt_name, "Version": "$Latest"}
    emitted_at = datetime.datetime.now(datetime.timezone.utc)

    # Positive control; Min=Desired=0 so the group never launches an instance.
    ok_resp = asg.create_auto_scaling_group(
        AutoScalingGroupName=name, LaunchTemplate=lt_ref,
        MinSize=0, MaxSize=1, DesiredCapacity=0, AvailabilityZones=[az], VPCZoneIdentifier=subnet,
    )
    ctx.on_cleanup(lambda: _delete_group(asg, name))
    ok_request_id = ok_resp["ResponseMetadata"]["RequestId"]
    assert ok_request_id, "the successful CreateAutoScalingGroup carried no RequestId"

    # Same name, different sizing, so the audited parameters cannot be copied from the first create.
    dup_err = _client_error(lambda: asg.create_auto_scaling_group(
        AutoScalingGroupName=name, LaunchTemplate=lt_ref,
        MinSize=0, MaxSize=2, DesiredCapacity=0, AvailabilityZones=[az], VPCZoneIdentifier=subnet,
    ), f"CreateAutoScalingGroup with the already-used name {name!r}")
    dup_code = dup_err.response["Error"]["Code"]
    dup_message = dup_err.response["Error"].get("Message", "")
    dup_request_id = dup_err.response["ResponseMetadata"].get("RequestId")
    assert dup_code == _DUP_SDK_CODE, (
        f"re-creating {name!r} raised {dup_code!r}, expected {_DUP_SDK_CODE!r}"
    )
    expected_dup_message = (
        f"AutoScalingGroup by this name already exists - A group with the name {name} already exists"
    )
    assert dup_message == expected_dup_message, (
        f"re-creating {name!r} raised message {dup_message!r}, expected {expected_dup_message!r}"
    )
    assert dup_request_id, "the rejected duplicate create carried no RequestId"

    bounds_err = _client_error(lambda: asg.update_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=3, MaxSize=1,
    ), f"UpdateAutoScalingGroup MinSize=3 MaxSize=1 on {name!r}")
    bounds_code = bounds_err.response["Error"]["Code"]
    bounds_message = bounds_err.response["Error"].get("Message", "")
    bounds_request_id = bounds_err.response["ResponseMetadata"].get("RequestId")
    assert bounds_code == _BOUNDS_SDK_CODE, (
        f"MinSize 3 > MaxSize 1 raised {bounds_code!r}, expected {_BOUNDS_SDK_CODE!r}"
    )
    assert bounds_message == _BOUNDS_SDK_MESSAGE, (
        f"MinSize 3 > MaxSize 1 raised message {bounds_message!r}, expected {_BOUNDS_SDK_MESSAGE!r}"
    )
    assert bounds_request_id, "the rejected update carried no RequestId"

    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    assert len(groups) == 1, f"expected exactly the one group {name!r}, got {groups!r}"
    sizing = {k: groups[0][k] for k in ("MinSize", "MaxSize", "DesiredCapacity")}
    assert sizing == {"MinSize": 0, "MaxSize": 1, "DesiredCapacity": 0}, (
        f"a REJECTED call changed the group: sizing is now {sizing!r}, expected the original "
        f"{{'MinSize': 0, 'MaxSize': 1, 'DesiredCapacity': 0}}"
    )

    lookup_rtt_s = None
    for _attempt in range(5):
        t_probe = time.monotonic()
        try:
            ct.lookup_events(MaxResults=1, LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "CreateAutoScalingGroup"}])
        except ClientError as err:
            if err.response["Error"]["Code"] != "ThrottlingException":
                raise
            time.sleep(2.0)
            continue
        lookup_rtt_s = time.monotonic() - t_probe
        break
    assert lookup_rtt_s is not None, "LookupEvents was throttled on 5 consecutive attempts"
    print(f"[measure] one LookupEvents round trip: {lookup_rtt_s:.3f}s")

    wanted = {
        ok_request_id: "CreateAutoScalingGroup",
        dup_request_id: "CreateAutoScalingGroup",
        bounds_request_id: "UpdateAutoScalingGroup",
    }
    found: dict[str, tuple[dict, dict]] = {}
    window_start = emitted_at - datetime.timedelta(minutes=5)
    t0 = time.monotonic()
    polls = scanned = throttled = 0
    while time.monotonic() - t0 < _INDEX_CEILING_S:
        polls += 1
        for event_name in sorted(set(wanted.values())):
            try:
                events = _lookup_all(
                    ct, StartTime=window_start,
                    EndTime=datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(minutes=5),
                    MaxResults=50,
                    LookupAttributes=[{"AttributeKey": "EventName",
                                       "AttributeValue": event_name}],
                )
            except ClientError as err:
                # LookupEvents allows 2 TPS per account and region; retry on the next poll.
                if err.response["Error"]["Code"] != "ThrottlingException":
                    raise
                throttled += 1
                continue
            scanned += len(events)
            for ev in events:
                rec = json.loads(ev.get("CloudTrailEvent") or "{}")
                params = rec.get("requestParameters") or {}
                if params.get("autoScalingGroupName") != name:
                    continue
                rid = rec.get("requestID")
                if rid in wanted and rid not in found:
                    found[rid] = (ev, rec)
                    print(f"[measure] {event_name} requestID {rid} indexed by "
                          f"{time.monotonic() - t0:.0f}s (poll {polls})")
        if len(found) == len(wanted):
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0
    print(f"[measure] all-or-timeout after {waited:.0f}s, {polls} polls, {scanned} events "
          f"scanned, {throttled} throttled lookups")

    missing = {rid: op for rid, op in wanted.items() if rid not in found}
    assert not missing, (
        f"{DATAPLANE_MARKER}: after {waited:.0f}s ({polls} LookupEvents polls, {scanned} events "
        f"scanned, {throttled} throttled; one lookup round trip took {lookup_rtt_s:.3f}s) CloudTrail "
        f"had not produced the audit record for {missing!r} (requestID -> eventName) of group "
        f"{name!r}. Found {sorted(found)!r}. Real AWS indexed all three within 60s."
    )

    ok_env, ok_rec = found[ok_request_id]
    assert ok_rec.get("eventSource") == "autoscaling.amazonaws.com", (
        f"success record eventSource is {ok_rec.get('eventSource')!r}"
    )
    assert ok_rec.get("eventName") == "CreateAutoScalingGroup", (
        f"success record eventName is {ok_rec.get('eventName')!r}"
    )
    assert ok_rec["requestParameters"].get("autoScalingGroupName") == name, (
        f"success record names group {ok_rec['requestParameters'].get('autoScalingGroupName')!r}, "
        f"expected {name!r}"
    )
    assert "errorCode" not in ok_rec, (
        f"the SUCCESSFUL CreateAutoScalingGroup was audited with errorCode "
        f"{ok_rec.get('errorCode')!r} -- a target that stamps errorCode on everything makes the "
        f"rejections' errorCode meaningless (lookup round trip {lookup_rtt_s:.3f}s, indexed within "
        f"{waited:.0f}s)"
    )
    assert "errorMessage" not in ok_rec, (
        f"the successful create carries errorMessage {ok_rec.get('errorMessage')!r}"
    )
    expected_ok_params = {
        "autoScalingGroupName": name,
        "launchTemplate": {"launchTemplateName": lt_name, "version": "$Latest"},
        "minSize": 0, "maxSize": 1, "desiredCapacity": 0, "availabilityZones": [az],
        "vPCZoneIdentifier": subnet,
    }
    assert ok_rec["requestParameters"] == expected_ok_params, (
        f"success record requestParameters {ok_rec['requestParameters']!r} != what was sent "
        f"{expected_ok_params!r}"
    )
    assert ok_env.get("EventSource") == "autoscaling.amazonaws.com", (
        f"success envelope EventSource is {ok_env.get('EventSource')!r}"
    )

    _assert_rejection_record(
        found[dup_request_id], label="duplicate CreateAutoScalingGroup",
        event_name="CreateAutoScalingGroup", sdk_code=dup_code, audit_code=_DUP_AUDIT_CODE,
        sdk_message=dup_message,
        sent={"autoScalingGroupName": name,
              "launchTemplate": {"launchTemplateName": lt_name, "version": "$Latest"},
              "minSize": 0, "maxSize": 2, "desiredCapacity": 0, "availabilityZones": [az],
              "vPCZoneIdentifier": subnet},
    )
    _assert_rejection_record(
        found[bounds_request_id], label="UpdateAutoScalingGroup MinSize>MaxSize",
        event_name="UpdateAutoScalingGroup", sdk_code=bounds_code,
        audit_code=_BOUNDS_AUDIT_CODE, sdk_message=bounds_message,
        sent={"autoScalingGroupName": name, "minSize": 3, "maxSize": 1},
    )


def _assert_rejection_record(found_pair, *, label, event_name, sdk_code, audit_code,
                             sdk_message, sent) -> None:
    _env, rec = found_pair
    assert rec.get("eventSource") == "autoscaling.amazonaws.com", (
        f"{label}: eventSource is {rec.get('eventSource')!r}"
    )
    assert rec.get("eventName") == event_name, (
        f"{label}: eventName is {rec.get('eventName')!r}, expected {event_name!r}"
    )
    assert "errorCode" in rec, (
        f"{label}: the audit record of a call that FAILED with {sdk_code!r} carries no errorCode; "
        f"record keys {sorted(rec)!r}"
    )
    assert rec["errorCode"] == audit_code, (
        f"{label}: audited errorCode is {rec['errorCode']!r}, expected {audit_code!r} -- the "
        f"measured audit counterpart of the SDK's {sdk_code!r} (the record names the exception, "
        f"the wire carries the awsQuery code; a target echoing {sdk_code!r} fails here)"
    )
    assert "errorMessage" in rec, f"{label}: the audit record carries no errorMessage"
    assert rec["errorMessage"] == sdk_message, (
        f"{label}: audited errorMessage {rec['errorMessage']!r} is not the message the SDK raised "
        f"{sdk_message!r}"
    )
    assert rec.get("requestParameters") == sent, (
        f"{label}: audited requestParameters {rec.get('requestParameters')!r} != what was "
        f"actually sent {sent!r}"
    )
    assert rec.get("responseElements") is None, (
        f"{label}: a rejected call has no response, yet responseElements is "
        f"{rec.get('responseElements')!r}"
    )
    assert rec.get("readOnly") is False, f"{label}: readOnly is {rec.get('readOnly')!r}"


def _client_error(fn, what: str) -> ClientError:
    """Return the ClientError ``fn`` raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"{what} was expected to be rejected, but it SUCCEEDED: {result!r}")


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion, bounded by _PAGE_CEILING pages."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _usable_az(ec2, instance_type: str, *, ctx) -> str:
    """An available AZ of the run's network that offers ``instance_type``."""
    offered = set()
    paginator = ec2.get_paginator("describe_instance_type_offerings")
    for page in paginator.paginate(LocationType="availability-zone",
                                   Filters=[{"Name": "instance-type",
                                             "Values": [instance_type]}]):
        offered.update(o["Location"] for o in page["InstanceTypeOfferings"])
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _delete_group(asg, name: str) -> None:
    """Force-delete the group and wait (bounded) until it is gone, so the launch template's
    teardown does not race it. Raises if it never converges."""
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        if "not found" not in exc.response["Error"].get("Message", ""):
            raise
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if not asg.describe_auto_scaling_groups(
                AutoScalingGroupNames=[name])["AutoScalingGroups"]:
            return
        time.sleep(5)
    raise RuntimeError(f"auto scaling group {name!r} still present 300s after ForceDelete")


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
