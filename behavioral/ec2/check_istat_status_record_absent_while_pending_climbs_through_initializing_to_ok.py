"""istat-status-record-absent-while-pending-climbs-through-initializing-to-ok."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "istat-status-record-absent-while-pending-climbs-through-initializing-to-ok"
GROUP = "launch-and-status-async-istat"
SERVICES = ["ec2"]

_ITYPE = "t3.micro"
_AL2023 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded")
#: AWS publishes no status-check deadline; t3 instances pass all three checks in a few minutes.
_OK_DEADLINE_S = 900
_FIELDS = ("SystemStatus", "InstanceStatus", "AttachedEbsStatus")

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """The (code, message) fn() raised. An unexpected SUCCESS raises rather than returning a falsy
    sentinel: an emulator that accepts what real AWS rejects must never read as a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
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
    """Bounded poll that RAISES on timeout -- never returns its last observation."""
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


def _retry_delete(fn, retries=300, delay=2.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind."""
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return None
            raise


def _usable_az(ec2, itype):
    """An AZ that is BOTH offered for itype and reported available -- both halves load-bearing."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [itype]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no AVAILABLE availability zone offers {itype!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _private_subnet(ctx, ec2, az, tagspec):
    """A VPC and subnet of this check's own making -- never the account's default VPC. Status
    checks are hypervisor-side probes and need no route out."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _states(ec2, ids):
    """State per id; an id not yet visible reads as 'unknown', never as 'terminated'."""
    out = {i: "unknown" for i in ids}
    try:
        for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=list(ids)):
            for resv in page["Reservations"]:
                for inst in resv["Instances"]:
                    out[inst["InstanceId"]] = inst["State"]["Name"]
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    return out


def _terminate_and_wait(ec2, ids, timeout_s=900):
    """Issue every terminate FIRST, then wait once for all of them to reach 'terminated'.

    A NotFound on a just-launched id is the eventual-consistency window, so it is retried (bounded)
    rather than swallowed. Raises on timeout.
    """
    ids = sorted(set(ids))
    if not ids:
        return
    deadline = time.monotonic() + timeout_s
    nf_deadline = time.monotonic() + 180
    while True:
        try:
            ec2.terminate_instances(InstanceIds=ids)
            break
        except ClientError as exc:
            if _code(exc) in _THROTTLE or (_code(exc) == "InvalidInstanceID.NotFound"
                                           and time.monotonic() < nf_deadline):
                time.sleep(2)
                continue
            raise
    states = {}
    while time.monotonic() < deadline:
        states = _states(ec2, ids)
        if all(s == "terminated" for s in states.values()):
            return
        time.sleep(2)
    raise AssertionError(f"instances not terminated within {timeout_s}s: {states!r}")


def _status_records(ec2, iid, **kw):
    """Every DescribeInstanceStatus record for iid, across every page. None while the new id is
    still inside EC2's NotFound eventual-consistency window."""
    out = []
    try:
        for page in ec2.get_paginator("describe_instance_status").paginate(
                InstanceIds=[iid], **kw):
            out.extend(page["InstanceStatuses"])
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    return out


def _summary(rec):
    """(SystemStatus, InstanceStatus, AttachedEbsStatus) summary values of one record."""
    return tuple((rec.get(f) or {}).get("Status") for f in _FIELDS)


def _is_still_ok(rec):
    """True when system and instance status read 'ok' and AttachedEbsStatus is 'ok' if present.

    EC2 serves AttachedEbsStatus intermittently across reads of a running instance.
    """
    sys_s, inst_s, ebs_s = _summary(rec)
    return (sys_s, inst_s) == ("ok", "ok") and ("AttachedEbsStatus" not in rec or ebs_s == "ok")


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceStatus has no record while pending, then 'initializing' climbing to all-'ok';
    a mixed real+fake id request is refused whole; stopped reads 'not-applicable' only with
    IncludeAllInstances; a restart resets the checks to 'initializing'.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-system-instance-status-check.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    run_tag = "sim2real-istat-" + uuid.uuid4().hex[:12]

    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": run_tag}]}]

    az = _usable_az(ec2, _ITYPE)
    ami = ssm.get_parameter(Name=_AL2023)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023} did not resolve to an AMI: {ami!r}"

    launched: list[str] = []
    try:
        subnet = _private_subnet(ctx, ec2, az, tagspec)
        ctx.on_cleanup(lambda: _terminate_and_wait(ec2, launched))
        inst = _call_with_retry(lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            TagSpecifications=tagspec("instance") + tagspec("volume"),
        ))["Instances"][0]
        iid = inst["InstanceId"]
        launched.append(iid)

        # --- 1. pending: no record ---------------------------------------------------
        # Read the status, then CONFIRM the instance was still pending after the read, so the
        # empty answer is provably about a pending instance and not a running one.
        pending_read = _poll(
            lambda: (_status_records(ec2, iid), _states(ec2, [iid])[iid]),
            lambda r: r[0] is not None and r[1] != "unknown",
            ctx=ctx, timeout_s=_budget_s(ctx, 60), interval_s=1.0,
            what=f"a DescribeInstanceStatus answer for the just-launched {iid}")
        records, state_after = pending_read
        assert state_after == "pending", (
            f"the first status read must be taken while {iid} is still pending to mean anything; "
            f"the instance was already {state_after!r} (records {records!r})"
        )
        assert records == [], (
            f"DescribeInstanceStatus must return NO record for a pending instance; for {iid} it "
            f"returned {records!r}"
        )

        # --- 2. initializing is observed, then each check reaches exactly ok ---------
        trajectory: list[tuple] = []

        def _observe():
            recs = _status_records(ec2, iid) or []
            assert len(recs) <= 1, f"more than one status record for {iid}: {recs!r}"
            if recs:
                summ = _summary(recs[0])
                if not trajectory or trajectory[-1] != summ:
                    trajectory.append(summ)
                return recs[0]
            return None

        ok_rec = _poll(_observe,
                       lambda r: r is not None and _summary(r) == ("ok", "ok", "ok"),
                       ctx=ctx, timeout_s=_budget_s(ctx, _OK_DEADLINE_S), interval_s=1.0,
                       what=(f"all of {_FIELDS} reaching exactly 'ok' for {iid} -- trajectory so "
                             f"far {trajectory!r}"))
        assert trajectory, f"no status record was ever observed for {iid}"
        first = dict(zip(_FIELDS, trajectory[0]))
        assert first["SystemStatus"] == "initializing", (
            f"the first status record for {iid} must show SystemStatus 'initializing', got "
            f"{first!r}; full trajectory {trajectory!r}"
        )
        assert first["InstanceStatus"] == "initializing", (
            f"the first status record for {iid} must show InstanceStatus 'initializing', got "
            f"{first!r}; full trajectory {trajectory!r}"
        )
        seen = {v for summ in trajectory for v in summ}
        assert "impaired" not in seen, (
            f"a healthy launch must never pass through 'impaired'; trajectory {trajectory!r}"
        )
        assert ok_rec["InstanceState"]["Name"] == "running", (
            f"an all-ok record must belong to a running instance, got {ok_rec['InstanceState']!r}"
        )
        for f in ("SystemStatus", "InstanceStatus"):
            details = {d["Name"]: d["Status"] for d in ok_rec[f].get("Details", [])}
            assert details == {"reachability": "passed"}, (
                f"{f} 'ok' must carry reachability 'passed', got {ok_rec[f]!r}"
            )

        # --- 3. three further reads leave ok unchanged -------------------------------
        # The read paths are eventually consistent with each other (a status=ok filter can return []
        # right after a plain all-ok read), so each read polls until it converges.
        def _converged(what, **kw):
            return _poll(
                lambda: _status_records(ec2, iid, **kw) or [],
                lambda recs: [r["InstanceId"] for r in recs] == [iid] and _is_still_ok(recs[0]),
                ctx=ctx, timeout_s=_budget_s(ctx, 180), interval_s=1.0,
                what=f"{what} converging to exactly [{iid!r}] with its checks still 'ok'")

        _converged("read 1 (filtered on status=ok)", Filters=[
            {"Name": "instance-status.status", "Values": ["ok"]},
            {"Name": "system-status.status", "Values": ["ok"]},
        ])
        include_all = _converged("read 2 (IncludeAllInstances)", IncludeAllInstances=True)
        assert include_all[0]["InstanceState"]["Name"] == "running", (
            f"read 2 must report the instance running, got {include_all[0]['InstanceState']!r}"
        )
        _converged("read 3 (filtered on reachability=passed)", Filters=[
            {"Name": "instance-status.reachability", "Values": ["passed"]},
            {"Name": "system-status.reachability", "Values": ["passed"]},
        ])
        impaired = _status_records(ec2, iid, Filters=[
            {"Name": "instance-status.status", "Values": ["impaired"]}])
        assert impaired == [], (
            f"a filter for instance-status=impaired must exclude the healthy {iid}, got "
            f"{impaired!r}"
        )

        # --- 4. a request naming one nonexistent id is refused whole ---------------
        # The short 8-hex form, deliberately: EC2 validates 17-hex ids beyond their length and may
        # answer Malformed, which would test the parser rather than the all-or-nothing refusal.
        fake = "i-" + uuid.uuid4().hex[:8]
        code, message = _error(lambda: ec2.describe_instance_status(InstanceIds=[iid, fake]))
        assert code == "InvalidInstanceID.NotFound", (
            f"DescribeInstanceStatus naming the real {iid} plus the nonexistent {fake} must be "
            f"refused with InvalidInstanceID.NotFound, got {code!r}"
        )
        assert message == f"The instance ID '{fake}' does not exist", message
        _converged("positive control: the same read naming only this instance")

        # --- 5. stopped: absent by default, not-applicable with IncludeAllInstances --
        ec2.stop_instances(InstanceIds=[iid])
        _poll(lambda: _states(ec2, [iid])[iid], lambda s: s == "stopped",
              ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=1.0, what=f"{iid} reaching 'stopped'")
        hidden = _status_records(ec2, iid)
        assert hidden == [], (
            f"DescribeInstanceStatus without IncludeAllInstances must return no record for the "
            f"stopped {iid}, got {hidden!r}"
        )
        shown = _status_records(ec2, iid, IncludeAllInstances=True)
        assert len(shown) == 1 and shown[0]["InstanceState"]["Name"] == "stopped", (
            f"IncludeAllInstances=True must return exactly one record for the stopped {iid} with "
            f"InstanceState 'stopped', got {shown!r}"
        )
        stopped_summary = dict(zip(_FIELDS, _summary(shown[0])))
        assert (stopped_summary["SystemStatus"], stopped_summary["InstanceStatus"]) == (
                "not-applicable", "not-applicable"), (
            f"a stopped instance's system and instance checks must read 'not-applicable', got "
            f"{stopped_summary!r} ({shown[0]!r})"
        )
        # For a stopped instance EC2 omits AttachedEbsStatus rather than reporting 'not-applicable'.
        assert "AttachedEbsStatus" not in shown[0], (
            f"a stopped instance's record must carry no AttachedEbsStatus member, got "
            f"{shown[0].get('AttachedEbsStatus')!r} ({shown[0]!r})"
        )

        # --- 6. restart: the record comes back initializing, not carried-over ok -----
        ec2.start_instances(InstanceIds=[iid])
        _poll(lambda: _states(ec2, [iid])[iid], lambda s: s == "running",
              ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=1.0,
              what=f"{iid} reaching 'running' again")
        back = _poll(lambda: _status_records(ec2, iid), lambda r: bool(r),
                     ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=1.0,
                     what=f"a status record for the restarted {iid}")
        restarted = dict(zip(_FIELDS, _summary(back[0])))
        assert restarted["InstanceStatus"] == "initializing", (
            f"after a stop/start the instance status check must be re-run from 'initializing', "
            f"not carried over; the first record read {restarted!r}"
        )
        assert restarted["SystemStatus"] == "initializing", (
            f"after a stop/start the system status check must be re-run from 'initializing'; the "
            f"first record read {restarted!r}"
        )
    finally:
        # Terminating the instance and releasing its subnet and VPC outlasts the bounded teardown,
        # so the cleanup chain runs here, on the failure path too.
        ctx.run_cleanups()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
