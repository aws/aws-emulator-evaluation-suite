"""obs-elbv2-3-refused-target-group-calls-are-audited-with-exception-suffixed-codes."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-elbv2-3-refused-target-group-calls-are-audited-with-exception-suffixed-codes"
GROUP = "eventing"
SERVICES = ["cloudtrail", "elbv2"]

# CloudTrail spells these errorCodes with the Exception suffix the SDK wire codes lack;
# deliberately not derived from the wire code.
_AUDIT_NOT_FOUND = "TargetGroupNotFoundException"
_AUDIT_DUPLICATE = "DuplicateTargetGroupNameException"
_WIRE_NOT_FOUND = "TargetGroupNotFound"
_WIRE_DUPLICATE = "DuplicateTargetGroupName"

# Event history can take up to ~15 minutes to index a record.
_LOOKUP_DEADLINE_S = 1200.0
_POLL_INTERVAL_S = 2.0
_PORT = 8080
_DUP_PORT = 9090

def _error(fn):
    """Return (code, message, request_id) for a call that MUST fail; raise if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        rid = exc.response.get("ResponseMetadata", {}).get("RequestId")
        return err.get("Code"), err.get("Message"), rid
    raise AssertionError(f"call unexpectedly SUCCEEDED; response={resp!r}")


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
    "axis:rejection",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CloudTrail audits two refused target-group calls with Exception-suffixed errorCodes, beside a
    successful create (no errorCode, minted ARN echoed, tags verbatim) and a distinct delete.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
    """
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    ct = ctx.client("cloudtrail")
    account = ctx.client("sts").get_caller_identity()["Account"]
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

    # An instance target group requires a VpcId; use a throwaway VPC, not the default one.
    vpc_name = ctx.unique_name("sim2real-xsvc-ctelb-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": vpc_name}, {"Key": "sim2real", "Value": CHECK}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    # Target-group names are <= 32 chars, alphanumeric and hyphens.
    name = ctx.unique_name("sim2real-ctelb-")[:32].rstrip("-")
    sent_tags = [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "odd key: =+/@", "Value": "v with spaces/=+:@-_. été"},
        {"Key": "max-len", "Value": ("abcdefghij" * 26)[:256]},
    ]
    created = elb.create_target_group(
        Name=name, Protocol="HTTP", Port=_PORT, VpcId=vpc_id, TargetType="instance",
        Tags=sent_tags,
    )
    tg_arn = created["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=tg_arn))
    create_rid = created["ResponseMetadata"]["RequestId"]

    # Positive API control: the real ARN resolves, and its tags read back as sent.
    live = elb.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"]
    assert [t["TargetGroupName"] for t in live] == [name], f"describe by ARN returned {live!r}"
    read_tags = elb.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    assert sorted((t["Key"], t["Value"]) for t in read_tags) == sorted(
        (t["Key"], t["Value"]) for t in sent_tags
    ), f"DescribeTags returned {read_tags!r}, sent {sent_tags!r}"

    # Refusal 1: a well-formed ARN in this account+region whose id does not exist.
    prefix, real_id = tg_arn.rsplit("/", 1)
    absent_id = "0123456789abcdef" if real_id != "0123456789abcdef" else "fedcba9876543210"
    absent_arn = f"{prefix}/{absent_id}"
    nf_code, nf_msg, nf_rid = _error(
        lambda: elb.describe_target_groups(TargetGroupArns=[absent_arn])
    )
    assert nf_code == _WIRE_NOT_FOUND, f"absent ARN raised {nf_code!r} ({nf_msg!r})"

    # Refusal 2: same name, different port. Capture a wrongful success so it is cleaned up.
    try:
        dup = elb.create_target_group(
            Name=name, Protocol="HTTP", Port=_DUP_PORT, VpcId=vpc_id, TargetType="instance"
        )
    except ClientError as exc:
        dup_code = exc.response["Error"]["Code"]
        dup_msg = exc.response["Error"].get("Message")
        dup_rid = exc.response["ResponseMetadata"]["RequestId"]
    else:
        dup_arn = dup["TargetGroups"][0]["TargetGroupArn"]
        if dup_arn != tg_arn:
            ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=dup_arn))
        raise AssertionError(f"duplicate name with a different port was ACCEPTED: {dup!r}")
    assert dup_code == _WIRE_DUPLICATE, f"duplicate name raised {dup_code!r} ({dup_msg!r})"
    same_name = elb.describe_target_groups(Names=[name])["TargetGroups"]
    assert [(t["TargetGroupArn"], t["Port"]) for t in same_name] == [(tg_arn, _PORT)], (
        f"the refused duplicate changed state: target groups named {name!r} are {same_name!r}"
    )

    # The delete, and the state transition it makes.
    delete_rid = elb.delete_target_group(TargetGroupArn=tg_arn)["ResponseMetadata"]["RequestId"]
    gone_code, gone_msg, _ = _error(lambda: elb.describe_target_groups(TargetGroupArns=[tg_arn]))
    assert gone_code == _WIRE_NOT_FOUND, f"deleted ARN raised {gone_code!r} ({gone_msg!r})"

    # Event history records management events without a trail; CloudTrail requestID equals
    # the SDK RequestId, so records join to calls by request id.
    found = _await_records(ct, start, {
        "create": ("CreateTargetGroup", create_rid),
        "not_found": ("DescribeTargetGroups", nf_rid),
        "duplicate": ("CreateTargetGroup", dup_rid),
        "delete": ("DeleteTargetGroup", delete_rid),
    })
    create_rec = _only(found, "create")
    nf_rec = _only(found, "not_found")
    dup_rec = _only(found, "duplicate")
    del_rec = _only(found, "delete")

    for label, rec in (("create", create_rec), ("not_found", nf_rec),
                       ("duplicate", dup_rec), ("delete", del_rec)):
        assert rec.get("eventSource") == "elasticloadbalancing.amazonaws.com", (
            f"{label}: eventSource {rec.get('eventSource')!r}"
        )
        assert rec.get("awsRegion") == ctx.region, f"{label}: awsRegion {rec.get('awsRegion')!r}"
        ident = rec.get("userIdentity") or {}
        assert ident.get("accountId") == account and ident.get("type"), (
            f"{label}: userIdentity {ident!r} does not name caller account {account!r}"
        )

    # The successful create: the positive control for every errorCode assertion below.
    assert create_rec.get("eventName") == "CreateTargetGroup", f"{create_rec.get('eventName')!r}"
    assert create_rec.get("readOnly") is False, f"create readOnly {create_rec.get('readOnly')!r}"
    assert "errorCode" not in create_rec and "errorMessage" not in create_rec, (
        f"successful create carries an error: {create_rec.get('errorCode')!r} "
        f"{create_rec.get('errorMessage')!r}"
    )
    params = create_rec.get("requestParameters") or {}
    assert params.get("name") == name and params.get("port") == _PORT, (
        f"create requestParameters {params!r}, expected name={name!r} port={_PORT}"
    )
    resp_tgs = (create_rec.get("responseElements") or {}).get("targetGroups") or []
    assert resp_tgs and resp_tgs[0].get("targetGroupArn") == tg_arn, (
        f"create responseElements.targetGroups {resp_tgs!r} does not echo minted ARN {tg_arn!r}"
    )
    audited_tags = params.get("tags")
    assert isinstance(audited_tags, list) and sorted(
        (t.get("key"), t.get("value")) for t in audited_tags
    ) == sorted((t["Key"], t["Value"]) for t in sent_tags), (
        f"tags mangled in requestParameters: audited {audited_tags!r}, sent {sent_tags!r}"
    )

    # Refusal 1 in the audit trail: the SHAPE name, not the wire code.
    assert nf_rec.get("eventName") == "DescribeTargetGroups", f"{nf_rec.get('eventName')!r}"
    assert nf_rec.get("errorCode") == _AUDIT_NOT_FOUND, (
        f"not-found audited errorCode {nf_rec.get('errorCode')!r}, expected {_AUDIT_NOT_FOUND!r} "
        f"(the wire said {nf_code!r})"
    )
    assert nf_rec.get("errorMessage") and nf_rec.get("errorMessage") == nf_msg, (
        f"not-found errorMessage {nf_rec.get('errorMessage')!r}, API said {nf_msg!r}"
    )
    assert nf_rec.get("responseElements") is None, f"{nf_rec.get('responseElements')!r}"
    assert nf_rec.get("readOnly") is True, f"describe readOnly {nf_rec.get('readOnly')!r}"
    assert (nf_rec.get("requestParameters") or {}).get("targetGroupArns") == [absent_arn], (
        f"not-found requestParameters {nf_rec.get('requestParameters')!r}"
    )

    # Refusal 2 in the audit trail.
    assert dup_rec.get("eventName") == "CreateTargetGroup", f"{dup_rec.get('eventName')!r}"
    assert dup_rec.get("errorCode") == _AUDIT_DUPLICATE, (
        f"duplicate audited errorCode {dup_rec.get('errorCode')!r}, expected {_AUDIT_DUPLICATE!r} "
        f"(the wire said {dup_code!r})"
    )
    assert dup_rec.get("errorMessage") and dup_rec.get("errorMessage") == dup_msg, (
        f"duplicate errorMessage {dup_rec.get('errorMessage')!r}, API said {dup_msg!r}"
    )
    assert dup_rec.get("responseElements") is None, f"{dup_rec.get('responseElements')!r}"
    assert dup_rec.get("readOnly") is False, f"duplicate readOnly {dup_rec.get('readOnly')!r}"
    dparams = dup_rec.get("requestParameters") or {}
    assert dparams.get("name") == name and dparams.get("port") == _DUP_PORT, (
        f"duplicate requestParameters {dparams!r}, expected name={name!r} port={_DUP_PORT}"
    )

    # The delete is its own event, about the same ARN, and succeeded.
    assert del_rec.get("eventName") == "DeleteTargetGroup", f"{del_rec.get('eventName')!r}"
    assert "errorCode" not in del_rec, f"delete audited as failed: {del_rec.get('errorCode')!r}"
    assert del_rec.get("readOnly") is False, f"delete readOnly {del_rec.get('readOnly')!r}"
    assert (del_rec.get("requestParameters") or {}).get("targetGroupArn") == tg_arn, (
        f"delete requestParameters {del_rec.get('requestParameters')!r}, expected {tg_arn!r}"
    )
    ids = [r.get("eventID") for r in (create_rec, nf_rec, dup_rec, del_rec)]
    assert len(set(ids)) == 4 and all(ids), f"audit records do not have distinct eventIDs: {ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
