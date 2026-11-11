"""obs-elbv2-3-idempotent-create-replay-is-audited-as-a-second-success-with-the-same-arn."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-elbv2-3-idempotent-create-replay-is-audited-as-a-second-success-with-the-same-arn"
GROUP = "eventing"
SERVICES = ["cloudtrail", "elbv2"]

# Event history can take up to ~15 minutes to index a record.
_LOOKUP_DEADLINE_S = 1200.0
_POLL_INTERVAL_S = 2.0
_PORT = 8080

def _lookup(ct, event_name, start):
    """Every event-history record for one EventName since `start`, fully paginated."""
    out, token = [], None
    while True:
        kw = {
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": event_name}],
            "StartTime": start,
            "MaxResults": 50,
        }
        if token:
            kw["NextToken"] = token
        for attempt in range(8):
            try:
                page = ct.lookup_events(**kw)
                break
            except ClientError as exc:
                # LookupEvents is limited to 2 TPS per account+region; back off on OUR throttle.
                if exc.response["Error"]["Code"] != "ThrottlingException" or attempt == 7:
                    raise
                time.sleep(0.5 * (2**attempt))
        out.extend(json.loads(e["CloudTrailEvent"]) for e in page.get("Events", []))
        token = page.get("NextToken")
        if not token:
            return out


def _await_records(ct, start, wanted):
    """Poll until every (event_name, request_id) in `wanted` is indexed; FAIL at the deadline."""
    deadline = time.monotonic() + _LOOKUP_DEADLINE_S
    found = {}
    while True:
        for event_name in sorted({n for n, _ in wanted.values()}):
            for rec in _lookup(ct, event_name, start):
                for label, (name, rid) in wanted.items():
                    if rec.get("eventName") == name and rec.get("requestID") == rid:
                        found.setdefault(label, {})[rec.get("eventID")] = rec
        missing = sorted(set(wanted) - set(found))
        if not missing:
            return found
        if time.monotonic() > deadline:
            raise AssertionError(
                f"CloudTrail event history never indexed {missing!r} within "
                f"{_LOOKUP_DEADLINE_S:.0f}s; found {sorted(found)!r}; wanted {wanted!r}"
            )
        time.sleep(_POLL_INTERVAL_S)


def _only(found, label):
    recs = list(found[label].values())
    assert len(recs) == 1, (
        f"{label}: expected exactly one record for its request id, got {len(recs)}: "
        f"{[r.get('eventID') for r in recs]!r}"
    )
    return recs[0]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An identical CreateTargetGroup replay returns the same ARN and is audited as a second,
    distinct, successful event whose responseElements name that pre-existing ARN.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html
    """
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    ct = ctx.client("cloudtrail")
    account = ctx.client("sts").get_caller_identity()["Account"]
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

    # An instance target group requires a VpcId; use a throwaway VPC, not the default one.
    vpc_name = ctx.unique_name("sim2real-xsvc-ctelb-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.94.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": vpc_name}, {"Key": "sim2real", "Value": CHECK}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    name = ctx.unique_name("sim2real-ctelb-")[:32].rstrip("-")
    spec = dict(
        Name=name, Protocol="HTTP", Port=_PORT, VpcId=vpc_id, TargetType="instance",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    first = elb.create_target_group(**spec)
    tg_arn = first["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=tg_arn))

    replay = elb.create_target_group(**spec)
    replay_arn = replay["TargetGroups"][0]["TargetGroupArn"]
    if replay_arn != tg_arn:
        ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=replay_arn))
    assert replay_arn == tg_arn, f"identical replay minted {replay_arn!r}, original {tg_arn!r}"

    listed = elb.describe_target_groups(Names=[name])
    assert [t["TargetGroupArn"] for t in listed["TargetGroups"]] == [tg_arn], (
        f"after the replay, target groups named {name!r} are {listed['TargetGroups']!r}"
    )

    first_rid = first["ResponseMetadata"]["RequestId"]
    replay_rid = replay["ResponseMetadata"]["RequestId"]
    describe_rid = listed["ResponseMetadata"]["RequestId"]
    assert first_rid != replay_rid, f"two calls shared request id {first_rid!r}"

    # CloudTrail requestID equals the SDK RequestId, so records join to calls by request id.
    found = _await_records(ct, start, {
        "first": ("CreateTargetGroup", first_rid),
        "replay": ("CreateTargetGroup", replay_rid),
        "describe": ("DescribeTargetGroups", describe_rid),
    })
    first_rec = _only(found, "first")
    replay_rec = _only(found, "replay")
    describe_rec = _only(found, "describe")

    for label, rec in (("first", first_rec), ("replay", replay_rec), ("describe", describe_rec)):
        assert rec.get("eventSource") == "elasticloadbalancing.amazonaws.com", (
            f"{label}: eventSource {rec.get('eventSource')!r}"
        )
        assert rec.get("awsRegion") == ctx.region, f"{label}: awsRegion {rec.get('awsRegion')!r}"
        assert (rec.get("userIdentity") or {}).get("accountId") == account, (
            f"{label}: userIdentity {rec.get('userIdentity')!r} does not name {account!r}"
        )
        assert "errorCode" not in rec, f"{label}: audited as failed: {rec.get('errorCode')!r}"

    for label, rec in (("first", first_rec), ("replay", replay_rec)):
        assert rec.get("readOnly") is False, f"{label}: readOnly {rec.get('readOnly')!r}"
        params = rec.get("requestParameters") or {}
        assert params.get("name") == name and params.get("port") == _PORT, (
            f"{label}: requestParameters {params!r}"
        )
        tgs = (rec.get("responseElements") or {}).get("targetGroups") or []
        assert [t.get("targetGroupArn") for t in tgs] == [tg_arn], (
            f"{label}: responseElements.targetGroups {tgs!r} do not name the one ARN {tg_arn!r}"
        )

    assert first_rec.get("eventID") != replay_rec.get("eventID"), (
        f"replay was not audited as its own event: both eventID {first_rec.get('eventID')!r}"
    )
    assert describe_rec.get("readOnly") is True, (
        f"DescribeTargetGroups audited readOnly={describe_rec.get('readOnly')!r}, expected True"
    )
    assert (describe_rec.get("requestParameters") or {}).get("names") == [name], (
        f"describe requestParameters {describe_rec.get('requestParameters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
