"""e2e-diagnose-alb-opensearch-stale-targets-with-alarm-config."""

from __future__ import annotations

import contextlib
import ipaddress
import time
import uuid
from pathlib import Path

from behavioral_harness import tags

CHECK = "e2e-diagnose-alb-opensearch-stale-targets-with-alarm-config"

#: A deploy-fronted lifecycle: its CloudFormation template lives under deployments/, and destroy
#: is ordered before the next apply.
GROUP = "deploy-e2e-lifecycle"

#: The SUBJECT services. cloudformation is the deploy front-end, infrastructure of the replay.
SERVICES = ["cloudwatch", "ec2", "elbv2", "opensearch"]

#: No phase brackets the diagnosis itself beyond the five below.
PHASES = ("deploy", "setup", "solve", "cleanup", "destroy")

#: The longest single wait: the VPC domain's create (measured ~15 min) and the stack delete that
#: waits on its ENIs. A ceiling to FAIL at, never an asserted latency.
_ROUND_DEADLINE_S = 2400

_HERE = Path(__file__).parent
TEMPLATE = _HERE / "deployments" / "alb-opensearch-stale-targets" / "template.json"

#: The two stale addresses the setup phase registers into both target groups (the domain's
#: pre-blue/green ENIs).
_STALE_IPS = ("10.80.4.37", "10.80.8.112")
#: The domain's subnet in the deployed template.
_DOMAIN_SUBNET = ipaddress.ip_network("10.80.8.0/22")


class _Trajectory:
    """The fixed read sequence a correct diagnosis follows, as SDK operations, in order.

    UPSTREAM_ARGV is the CLI form of the same reads; nothing executes it.
    """

    OPS = (
        ("cloudwatch", "DescribeAlarms"),
        ("elbv2", "DescribeLoadBalancers"),
        ("elbv2", "DescribeTargetGroups"),
        ("elbv2", "DescribeTargetHealth"),
        ("opensearch", "DescribeDomain"),
        ("ec2", "DescribeNetworkInterfaces"),
    )
    UPSTREAM_ARGV = (
        "aws cloudwatch describe-alarms --alarm-names $ALARM_NAME --query MetricAlarms[0].Dimensions",
        "aws elbv2 describe-load-balancers --query LoadBalancers[?DNSName=='$ALB_DNS'].LoadBalancerArn | [0]",
        "aws elbv2 describe-load-balancers --load-balancer-arns $ALB_ARN --query LoadBalancers[0].VpcId",
        "aws elbv2 describe-target-groups --load-balancer-arn $ALB_ARN --query TargetGroups[].TargetGroupArn",
        "aws elbv2 describe-target-groups --target-group-arns $TG --query TargetGroups[0].TargetGroupName",
        "aws elbv2 describe-target-health --target-group-arn $TG --query TargetHealthDescriptions[].Target.Id",
        "aws elbv2 describe-target-health --target-group-arn $TG --query TargetHealthDescriptions[].TargetHealth.State",
        "aws opensearch describe-domain --domain-name $DOMAIN_NAME --query DomainStatus.Endpoints.vpc || DomainStatus.Endpoint",
        "aws ec2 describe-network-interfaces --filters Name=vpc-id,Values=$VPC_ID --query NetworkInterfaces[].PrivateIpAddress",
        "aws ec2 describe-network-interfaces --filters Name=vpc-id,Values=$VPC_ID Name=requester-id,Values=amazon-elasticsearch "
        "Name=description,Values='ES $DOMAIN_NAME' --query NetworkInterfaces[].PrivateIpAddress",
    )


@tags("axis:happy-path", "concern:e2e", "concern:deploy", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """Deploy, re-stale, diagnose and restore an ALB-fronted VPC OpenSearch domain end to end:
    the deployed alarm's configuration, re-pointed groups failing health checks, a read-only
    diagnosis tracing registered IPs to no live ENI, and a restore to empty before destroy."""
    assert not _cloudformation_unavailable(ctx), (
        "CloudFormation does not answer on this target; the lifecycle's deploy front-end is missing"
    )
    tok = ctx.unique_name("sim2real-ao-")
    cw = ctx.client("cloudwatch")
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")

    j = _Journal(PHASES)
    ctx.on_cleanup(j.dump)  # registered FIRST -> pops LAST -> prints even after a timeout

    with j.phase("deploy"):
        est = _deploy_estate(ctx, tok)
        out = est["outputs"]
        want_out = {"VpcId", "DomainName", "DomainEndpoint", "AlbDnsName", "AlbArn",
                    "DashboardsTgArn", "ApiTgArn", "AlarmName"}
        assert set(out) == want_out, f"stack outputs are {sorted(out)!r}, expected {sorted(want_out)!r}"
        assert (out["DomainName"], out["AlarmName"]) == (tok, f"{tok}-unhealthy-hosts"), (
            f"outputs {out!r} do not name the minted domain and alarm"
        )
        alarm = _alarm(cw, out["AlarmName"])
        got = {k: alarm.get(k) for k in ("Namespace", "MetricName", "Statistic", "Period",
                                          "EvaluationPeriods", "Threshold", "ComparisonOperator",
                                          "TreatMissingData")}
        assert got == {"Namespace": "AWS/ApplicationELB", "MetricName": "UnHealthyHostCount",
                       "Statistic": "Maximum", "Period": 60, "EvaluationPeriods": 2, "Threshold": 0.0,
                       "ComparisonOperator": "GreaterThanThreshold", "TreatMissingData": "breaching"}, (
            f"the deployed alarm reads {got!r}"
        )
        dims = {d["Name"]: d["Value"] for d in alarm["Dimensions"]}
        assert dims == {"LoadBalancer": out["AlbArn"].split(":loadbalancer/", 1)[1],
                        "TargetGroup": out["DashboardsTgArn"].rsplit(":", 1)[1]}, (
            f"the alarm's dimensions {dims!r} should be the ALB's and dashboards group's full names"
        )
        for arn in (out["DashboardsTgArn"], out["ApiTgArn"]):
            assert sorted(_health(elb, arn)) == sorted(_STALE_IPS), (
                f"the stack registers the stale pair in {arn!r}, it holds {sorted(_health(elb, arn))!r}"
            )

    with j.phase("setup"):
        # Re-stale the estate: deregister whatever is registered, then register the stale pair.
        enis = ec2.describe_network_interfaces(Filters=[
            {"Name": "description", "Values": [f"ES {out['DomainName']}"]},
            {"Name": "status", "Values": ["in-use"]}])["NetworkInterfaces"]
        actual = sorted(e["PrivateIpAddress"] for e in enis)
        assert actual, f"the active domain should hold at least one in-use ENI, found {enis!r}"
        assert all(ipaddress.ip_address(ip) in _DOMAIN_SUBNET for ip in actual), (
            f"the domain's ENI addresses {actual!r} should come from its subnet {_DOMAIN_SUBNET}"
        )
        assert not set(actual) & set(_STALE_IPS), (
            f"the domain's live ENIs {actual!r} must not hold a stale address {_STALE_IPS!r}"
        )
        for arn in (out["DashboardsTgArn"], out["ApiTgArn"]):
            current = [{"Id": d["Target"]["Id"], "Port": d["Target"]["Port"]} for d in
                       elb.describe_target_health(TargetGroupArn=arn)["TargetHealthDescriptions"]]
            if current:
                elb.deregister_targets(TargetGroupArn=arn, Targets=current)
            elb.register_targets(TargetGroupArn=arn, Targets=[{"Id": ip, "Port": 443} for ip in _STALE_IPS])
        # The estate solve() is handed: both groups' stale pair failing health checks.
        # The state is the durable verdict; the reason is not (measured: one stale address read
        # Target.Timeout in one group and Target.FailedHealthChecks in the other, same ALB).
        failed = {ip: "unhealthy" for ip in _STALE_IPS}

        def states():
            return tuple({ip: s for ip, (s, _r) in _health(elb, arn).items()}
                         for arn in (out["DashboardsTgArn"], out["ApiTgArn"]))

        settled = _poll(states, lambda h: h == (failed, failed), timeout_s=600, interval_s=10,
                        description="both groups' re-registered stale targets failing health checks")
        assert settled == (failed, failed), f"after setup the groups read {settled!r}"

    with j.phase("solve"):
        answer, fired = _solve(ctx, out["AlbDnsName"], out["DomainName"], out["AlarmName"])
        # the fixed sequence below is sufficient on its own; nothing outside it is needed.
        assert fired == _Trajectory.OPS, (
            f"the trajectory fired {fired!r}, the fixed sequence is {_Trajectory.OPS!r}"
        )
        assert (answer["alb_arn"], answer["vpc"]) == (out["AlbArn"], out["VpcId"]), (
            f"the DNS-name lookup should find the estate's ALB in its VPC, found {answer!r}"
        )
        assert answer["alarm_group"] == f"{tok}-dash", (
            f"the alarm's TargetGroup dimension should name the dashboards group, found {answer!r}"
        )
        assert sorted(answer["groups"]) == sorted([f"{tok}-dash", f"{tok}-api"]), (
            f"the ALB's target groups are {sorted(answer['groups'])!r}"
        )
        for name, (ips, states) in answer["groups"].items():
            assert sorted(ips) == sorted(_STALE_IPS), f"{name} registers {ips!r}, expected the stale pair"
            assert states == ["unhealthy", "unhealthy"], f"{name}'s targets read {states!r}"
        registered = {ip for ips, _s in answer["groups"].values() for ip in ips}
        live, domain_ips = set(answer["live_eni_ips"]), set(answer["domain_eni_ips"])
        assert answer["endpoint_kind"] == "vpc", (
            f"a VPC domain answers Endpoints.vpc and no public Endpoint, got {answer['endpoint_kind']!r}"
        )
        assert domain_ips and domain_ips <= live, (
            f"the domain's ENI IPs {sorted(domain_ips)!r} should be a non-empty subset of the VPC's "
            f"live ENI IPs {sorted(live)!r}"
        )
        # The diagnosis itself: no registered target address is attached to any live ENI, and the
        # domain's current ENI addresses are different ones.
        assert not registered & live, (
            f"registered targets {sorted(registered)!r} should map to no live ENI, but "
            f"{sorted(registered & live)!r} do"
        )
        assert not registered & domain_ips, (
            f"the domain's ENI IPs {sorted(domain_ips)!r} should differ from the registered "
            f"{sorted(registered)!r}"
        )

    with j.phase("cleanup"):
        # cleanup undoes what setup did OUTSIDE the IaC, observably: both groups drain to empty.
        # Cosmetic for destroy (CloudFormation deletes groups with targets),
        # so the drain delay is dropped to 0 first rather than waiting out the 300 s default.
        for arn in (out["DashboardsTgArn"], out["ApiTgArn"]):
            elb.modify_target_group_attributes(TargetGroupArn=arn, Attributes=[
                {"Key": "deregistration_delay.timeout_seconds", "Value": "0"}])
            elb.deregister_targets(TargetGroupArn=arn, Targets=[{"Id": ip, "Port": 443} for ip in _STALE_IPS])
        drained = _poll(lambda: (_health(elb, out["DashboardsTgArn"]), _health(elb, out["ApiTgArn"])),
                        lambda h: h == ({}, {}), timeout_s=300, interval_s=5,
                        description="both target groups draining to empty")
        assert drained == ({}, {}), f"the groups still hold targets: {drained!r}"

    with j.phase("destroy"):
        assert est["destroy"]() == 0, "stack deletion did not reach DELETE_COMPLETE"
        got = _absent_error(lambda: ctx.client("cloudformation").describe_stack_resources(
            StackName=est["stack"]))
        assert got == ("ValidationError", f"Stack with id {est['stack']} does not exist"), (
            f"CloudFormation should report the deleted stack {est['stack']!r} as gone, got {got!r}"
        )
        # A real second DeleteStack call (not a memoized skip) on the already-gone stack must
        # itself be a clean no-op.
        try:
            ctx.client("cloudformation").delete_stack(StackName=est["stack"])
        except Exception as exc:
            raise AssertionError(
                f"a second DeleteStack on the already-deleted stack {est['stack']!r} should be a "
                f"no-op, raised {exc!r}"
            ) from exc
        got2 = _absent_error(lambda: ctx.client("cloudformation").describe_stack_resources(
            StackName=est["stack"]))
        assert got2 == ("ValidationError", f"Stack with id {est['stack']} does not exist"), (
            f"after a second DeleteStack the stack {est['stack']!r} should still read gone, got "
            f"{got2!r}"
        )


# ===== the diagnosis sequence, replayed =====
def _solve(ctx, alb_dns: str, domain: str, alarm_name: str) -> tuple[dict, tuple]:
    """Replay _Trajectory and return (what it found, the ops it fired), for run() to grade."""
    cw, elb, ec2 = ctx.client("cloudwatch"), ctx.client("elbv2"), ctx.client("ec2")
    fired: list[tuple[str, str]] = []

    def op(service, name):
        if (service, name) not in fired:
            fired.append((service, name))

    op("cloudwatch", "DescribeAlarms")
    alarm_dims = {d["Name"]: d["Value"] for d in
                  cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["Dimensions"]}

    op("elbv2", "DescribeLoadBalancers")
    lbs = [lb for page in elb.get_paginator("describe_load_balancers").paginate()
           for lb in page["LoadBalancers"] if lb["DNSName"] == alb_dns]
    assert len(lbs) == 1, f"exactly one load balancer should answer to {alb_dns!r}, found {lbs!r}"
    alb_arn = lbs[0]["LoadBalancerArn"]
    vpc = elb.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["VpcId"]

    op("elbv2", "DescribeTargetGroups")
    tg_arns = [t["TargetGroupArn"] for t in elb.describe_target_groups(LoadBalancerArn=alb_arn)["TargetGroups"]]
    groups, alarm_group = {}, None
    for arn in tg_arns:
        name = elb.describe_target_groups(TargetGroupArns=[arn])["TargetGroups"][0]["TargetGroupName"]
        op("elbv2", "DescribeTargetHealth")
        descs = elb.describe_target_health(TargetGroupArn=arn)["TargetHealthDescriptions"]
        groups[name] = ([d["Target"]["Id"] for d in descs], [d["TargetHealth"]["State"] for d in descs])
        if arn.rsplit(":", 1)[1] == alarm_dims.get("TargetGroup"):
            alarm_group = name

    op("opensearch", "DescribeDomain")
    status = ctx.client("opensearch").describe_domain(DomainName=domain)["DomainStatus"]
    endpoint_kind = ("vpc" if "vpc" in (status.get("Endpoints") or {}) and "Endpoint" not in status
                     else f"Endpoints={status.get('Endpoints')!r} Endpoint={status.get('Endpoint')!r}")

    op("ec2", "DescribeNetworkInterfaces")

    def ips(filters):
        return sorted({n["PrivateIpAddress"] for page in ec2.get_paginator("describe_network_interfaces")
                       .paginate(Filters=filters) for n in page["NetworkInterfaces"]})

    vpc_filter = {"Name": "vpc-id", "Values": [vpc]}
    live = ips([vpc_filter])
    domain_ips = ips([vpc_filter, {"Name": "requester-id", "Values": ["amazon-elasticsearch"]},
                      {"Name": "description", "Values": [f"ES {domain}"]}])
    return ({"alarm_group": alarm_group, "alb_arn": alb_arn, "vpc": vpc, "groups": groups,
             "endpoint_kind": endpoint_kind, "live_eni_ips": live, "domain_eni_ips": domain_ips},
            tuple(fired))


# ===== self-contained helpers =====
class _PhaseError(Exception):
    """A non-assertion failure, re-raised with its phase named and its own message preserved."""


class _Journal:
    """Phase attribution for an engine that records ONE verdict per check: an AssertionError stays
    one, anything else keeps its original text."""

    def __init__(self, phases: tuple[str, ...]) -> None:
        self.phases, self.log, self.cur = phases, [], None

    @contextlib.contextmanager
    def phase(self, name: str):
        i, t0 = self.phases.index(name) + 1, time.monotonic()
        self.cur = name
        print(f"  [phase {i}/{len(self.phases)} {name}]", flush=True)
        try:
            yield
        except AssertionError as exc:
            self._note(name, i, t0, "MISMATCH")
            raise AssertionError(f"[phase {i}/{len(self.phases)} {name}] {exc}") from exc
        except Exception as exc:
            self._note(name, i, t0, "ERROR")
            raise _PhaseError(
                f"[phase {i}/{len(self.phases)} {name}] {type(exc).__name__}: {exc}"
            ) from exc
        self._note(name, i, t0, "PASS")

    def _note(self, name: str, i: int, t0: float, verdict: str) -> None:
        self.log.append((name, i, round((time.monotonic() - t0) * 1000, 1), verdict))

    def dump(self) -> None:
        print("  [phases] " + " ".join(f"{i}:{n}={v}/{ms:.0f}ms" for n, i, ms, v in self.log),
              flush=True)
        if len(self.log) < len(self.phases):
            print(f"  [phases] DEPTH_REACHED={len(self.log)}/{len(self.phases)} "
                  f"(stopped in {self.cur!r})", flush=True)


def _poll(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _absent_error(fn) -> tuple[str, str]:
    """The (code, message) fn() raises; a success fails the check -- for asserting an ABSENCE."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


def _cloudformation_unavailable(ctx) -> bool:
    from botocore.exceptions import ClientError

    try:
        ctx.client("cloudformation").list_stacks(StackStatusFilter=["CREATE_COMPLETE"])
    except ClientError:
        return False
    except Exception:  # noqa: BLE001 - only "does not answer at all" counts
        return True
    return False


def _alarm(cw, name: str) -> dict:
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(found) == 1, f"alarm {name!r} should be described exactly once, got {found!r}"
    return found[0]


def _health(elb, tg_arn: str) -> dict:
    """{ip: (state, reason)} for every registered target."""
    return {d["Target"]["Id"]: (d["TargetHealth"]["State"], d["TargetHealth"].get("Reason"))
            for d in elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]}


def _stack_status(ctx, stack: str) -> str:
    from botocore.exceptions import ClientError

    try:
        stacks = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise
    return stacks[0]["StackStatus"]


def _deploy_estate(ctx, tok: str) -> dict:
    """Apply the template; register the delete BEFORE the create; return outputs."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    stack = tok
    state = {"deleted": None}

    def _delete() -> int:
        """Idempotent-once by STATE, so the cleanup net below is a real destroy only when the
        destroy phase has not already run it. A VPC domain's ENIs can outlive the domain by
        minutes, so a DELETE_FAILED on the subnets is retried with a fresh delete within the same
        bounded deadline."""
        if state["deleted"] is not None:
            return state["deleted"]
        deadline = time.monotonic() + _ROUND_DEADLINE_S
        while True:
            cfn.delete_stack(StackName=stack)
            try:
                _poll(lambda: _stack_status(ctx, stack), lambda s: s in ("GONE", "DELETE_FAILED"),
                      timeout_s=max(60.0, deadline - time.monotonic()), interval_s=15,
                      description=f"stack {stack} deleted")
            except AssertionError:
                state["deleted"] = 1
                return 1
            if _stack_status(ctx, stack) == "GONE":
                state["deleted"] = 0
                return 0
            if time.monotonic() >= deadline:
                state["deleted"] = 1
                return 1

    def _delete_net() -> None:
        rc = _delete()
        assert rc == 0, f"stack {stack} did not reach DELETE_COMPLETE"

    ctx.on_cleanup(_delete_net)  # BEFORE the create: a check killed mid-apply otherwise strands it
    password = f"Fl1nt-{uuid.uuid4().hex[:10]}!"
    cfn.create_stack(StackName=stack, TemplateBody=TEMPLATE.read_text(),
                     Parameters=[{"ParameterKey": "Token", "ParameterValue": tok},
                                 {"ParameterKey": "MasterPassword", "ParameterValue": password}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    status = _poll(lambda: _stack_status(ctx, stack),
                   lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE",
                                   "ROLLBACK_FAILED", "GONE"),
                   timeout_s=_ROUND_DEADLINE_S, interval_s=20,
                   description=f"stack {stack} reaching a terminal state")
    if status != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
                  if e["ResourceStatus"].endswith("FAILED")][:5]
        raise AssertionError(f"stack {stack} reached {status!r}; failed resources {failed!r}")
    outs = {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    return {"stack": stack, "outputs": outs, "destroy": _delete}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
