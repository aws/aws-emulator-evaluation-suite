"""managed-insight-rule-report-reflects-applied-template."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-insight-rule-report-reflects-applied-template"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


# Marks a resource the target accepted but never converged, so it reads as a fidelity failure.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state, returned for ``from exc``."""
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A managed rule template applied to a VPC endpoint service shows up ENABLED, and
    GetInsightRuleReport and DescribeInsightRules both serve that server-generated rule.
    """
    # Managed rule templates exist only for specific resource types, such as PrivateLink services.
    try:
        prereqs = _provision_vpc_endpoint_service(ctx)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 - infra provisioning is a soft prerequisite
        raise AssertionError(f"could not provision a VPC endpoint service prerequisite: {exc}") from exc

    cw = ctx.client("cloudwatch")
    resource_arn = prereqs["resource_arn"]

    available = cw.list_managed_insight_rules(ResourceARN=resource_arn).get("ManagedRules", [])
    if not available:
        raise AssertionError(
            "no managed Contributor Insights rule templates are available for VPC endpoint "
            "services in this account/region"
        )
    template_name = available[0]["TemplateName"]

    put_resp = cw.put_managed_insight_rules(
        ManagedRules=[{"ResourceARN": resource_arn, "TemplateName": template_name}]
    )
    if put_resp.get("Failures"):
        failure = put_resp["Failures"][0]
        if failure.get("ExceptionType") == "LimitExceededException":
            # The quota counts every rule, enabled or disabled, so stale rules must be deleted.
            _disable_stale_sim2real_rules(cw)
            put_resp = cw.put_managed_insight_rules(
                ManagedRules=[{"ResourceARN": resource_arn, "TemplateName": template_name}]
            )
    assert not put_resp.get("Failures"), f"PutManagedInsightRules reported failures: {put_resp['Failures']}"

    ctx.on_cleanup(lambda: _best_effort_delete_managed_rule(cw, resource_arn))

    rule_state = _poll_until(
        lambda: cw.list_managed_insight_rules(ResourceARN=resource_arn)["ManagedRules"][0].get("RuleState"),
        lambda state: state is not None and state.get("State") == "ENABLED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    rule_name = rule_state["RuleName"]

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=1)
    # Without Metrics, CloudWatch omits MetricDatapoints entirely rather than returning [].
    report = cw.get_insight_rule_report(
        RuleName=rule_name, StartTime=start, EndTime=end, Period=300, Metrics=["Sum"]
    )
    assert "Contributors" in report and isinstance(report["Contributors"], list), (
        f"GetInsightRuleReport for the managed rule {rule_name!r} did not return the expected "
        f"Contributors schema: {report}"
    )
    assert "MetricDatapoints" in report and isinstance(report["MetricDatapoints"], list), (
        f"GetInsightRuleReport for the managed rule {rule_name!r} did not return the expected "
        f"MetricDatapoints schema: {report}"
    )

    described = {r["Name"]: r for r in _list_all_insight_rules(cw)}
    assert rule_name in described, f"managed rule {rule_name!r} not visible via DescribeInsightRules"
    assert described[rule_name]["State"] == "ENABLED", (
        f"DescribeInsightRules reports state {described[rule_name]['State']!r} for managed rule "
        f"{rule_name!r}, expected ENABLED"
    )


def _best_effort_delete_managed_rule(cw: Any, resource_arn: str) -> None:
    """Teardown: delete every managed rule left on the resource; a rule already gone is reported
    in the response's Failures, and only the resource's not-found is tolerated."""
    try:
        managed = cw.list_managed_insight_rules(ResourceARN=resource_arn).get("ManagedRules", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    for entry in managed:
        state = entry.get("RuleState")
        if state:
            cw.delete_insight_rules(RuleNames=[state["RuleName"]])


def _disable_stale_sim2real_rules(cw: Any) -> None:
    """Delete stray "sim2real-behav-" Contributor Insights rules to free the total-rules quota."""
    token = None
    to_delete: list[str] = []
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.describe_insight_rules(**kwargs)
        for rule in resp.get("InsightRules", []):
            name = rule.get("Name", "")
            if "sim2real-behav-" in name:
                to_delete.append(name)
        token = resp.get("NextToken")
        if not token:
            break
    # DeleteInsightRules rejects oversized RuleNames batches (BATCH_REQUEST_TOO_LARGE).
    _BATCH_LIMIT = 20
    for i in range(0, len(to_delete), _BATCH_LIMIT):
        cw.delete_insight_rules(RuleNames=to_delete[i : i + _BATCH_LIMIT])


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _delete_retrying_dependency_violation(delete_call, *, timeout_s=90.0, interval_s=6.0) -> None:
    """Retry a delete on DependencyViolation only: the NLB's ENIs linger after the deleted waiter.

    Any other error propagates, so it is not masked as an ENI-release race.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete_call()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _list_all_insight_rules(cw: Any) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.describe_insight_rules(**kwargs)
        rules.extend(resp.get("InsightRules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return rules


def _provision_vpc_endpoint_service(ctx: Any) -> dict[str, str]:
    """Create the minimum viable VPC PrivateLink endpoint service (VPC + subnet + internal NLB)."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    name_tag = ctx.unique_name("sim2real-behav-mir-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.191.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name_tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying_dependency_violation(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.191.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name_tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_retrying_dependency_violation(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    )

    nlb = elbv2.create_load_balancer(
        Name=name_tag[:32].rstrip("-"),
        Subnets=[subnet_id],
        Scheme="internal",
        Type="network",
        Tags=[{"Key": "Name", "Value": name_tag}],
    )["LoadBalancers"][0]
    nlb_arn = nlb["LoadBalancerArn"]

    def _delete_nlb_and_wait() -> None:
        elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
        elbv2.get_waiter("load_balancers_deleted").wait(
            LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_delete_nlb_and_wait)

    active = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )
    if active != "active":
        raise _never_ready(
            "network load balancer never reached the active state",
        )

    svc = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=False,
        TagSpecifications=[
            {"ResourceType": "vpc-endpoint-service", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ],
    )["ServiceConfiguration"]
    service_id = svc["ServiceId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))

    _poll_until(
        lambda: ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])[
            "ServiceConfigurations"
        ][0]["ServiceState"],
        lambda state: state == "Available",
        timeout_s=120.0,
        interval_s=5.0,
    )

    resource_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:vpc-endpoint-service/{service_id}"
    return {"resource_arn": resource_arn, "service_id": service_id, "nlb_arn": nlb_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
