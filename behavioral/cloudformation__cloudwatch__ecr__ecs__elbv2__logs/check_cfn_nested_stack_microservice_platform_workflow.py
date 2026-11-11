"""cfn-nested-stack-microservice-platform-workflow."""

from __future__ import annotations

import datetime
import http.client
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-nested-stack-microservice-platform-workflow"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "cloudwatch", "ecr", "ecs", "elbv2", "logs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"

_PARENT = "platform-parent.yaml"
_NETWORK = "platform-network.yaml"
_SERVICE = "platform-service.yaml"
_OBSERVABILITY = "platform-observability.yaml"
_ROLLBACK_PARENT = "platform-parent-rollback.yaml"
_INVALID_CHILD = "platform-child-invalid.yaml"

#: ECR Public busybox: a tiny image an anonymous Fargate pull can always fetch, so a check about
#: nested stacks is not also a check about registry credentials.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

#: Not in the accepted CloudWatch Logs retention set (1, 3, 5, 7, 14, 30, ... 3653).
_BAD_RETENTION = "4"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Nested child stacks wired only through the parent's GetAtt on their Outputs serve HTTP via the
    ALB and Fargate, a child failure rolls the parent back, and the parent's drift omits child stacks.
    """
    legs = _Legs(ctx, total=12)

    vpc_id, subnets = _owned_vpc(ctx, ctx.client("ec2"), "10.184.0.0/24")
    ingress_list = _ingress_prefix_list(ctx, ctx.client("ec2"))

    lb_name = _xname(ctx, "alb")
    tg_name = _xname(ctx, "tg")
    sg_name = _xname(ctx, "sg")
    cluster_name = _xname(ctx, "cluster")
    service_name = _xname(ctx, "svc")
    task_family = _xname(ctx, "td")
    repo_name = _xname(ctx, "repo")
    log_group = _xname(ctx, "lg")
    namespace = "SimParity/Platform"
    metric_name = "ServiceStarted" + ctx.unique_name("")[:10]
    alarm_name = _xname(ctx, "alarm")
    marker_v1 = _xname(ctx, "mark1")
    marker_v2 = _xname(ctx, "mark2")

    ctx.on_cleanup(
        lambda: _swallow(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    )

    urls = legs.hard("bootstrap", lambda: _upload_child_templates(ctx))
    # The failure-injection parent shares nothing with the platform, so it rolls back during the deploy.
    rollback = _start_rollback_parent(ctx, urls, namespace)

    params = {
        "NetworkTemplateUrl": urls[_NETWORK],
        "ServiceTemplateUrl": urls[_SERVICE],
        "ObservabilityTemplateUrl": urls[_OBSERVABILITY],
        "VpcId": vpc_id,
        "SubnetIds": ",".join(subnets),
        "LoadBalancerName": lb_name,
        "TargetGroupName": tg_name,
        "SecurityGroupName": sg_name,
        "IngressPrefixListId": ingress_list,
        "ClusterName": cluster_name,
        "ServiceName": service_name,
        "TaskFamily": task_family,
        "RepositoryName": repo_name,
        "ContainerImage": _PUBLIC_IMAGE,
        "Marker": marker_v1,
        "DesiredCount": "1",
        "LogGroupName": log_group,
        "RetentionDays": "7",
        "MetricNamespace": namespace,
        "MetricName": metric_name,
        "AlarmName": alarm_name,
    }

    stack = legs.hard(
        "deploy",
        lambda: _deploy_cfn(
            ctx, (DEPLOYMENTS / _PARENT).read_text(), parameters=params, timeout_s=2400.0
        ),
    )
    parent = stack["stack_name"]
    parent_id = stack["stack_id"]
    outputs = stack["outputs"]
    # Registered before the deadline-delete below so it pops (runs) AFTER it: the parent's own
    # StackId is already known here, so this does not race the deadline-delete for it the way
    # _deploy_cfn's internal capture-by-describe would.
    ctx.on_cleanup(lambda: _delete_stack_task_definitions(ctx, parent_id))
    ctx.on_cleanup(lambda: _delete_stack_deadline(ctx, parent, timeout_s=1800.0))

    state: dict[str, Any] = {}

    legs.step("children", lambda: _assert_children_are_real_stacks(ctx, parent, repo_name, state))
    legs.step(
        "crossref",
        lambda: _assert_cross_stack_references_resolved(ctx, parent, outputs, log_group, state),
        requires=("children",),
    )
    legs.step(
        "wiring",
        lambda: _assert_platform_serves_http(ctx, outputs, cluster_name, marker_v1),
        requires=("crossref",),
    )
    legs.step("logs", lambda: _assert_structured_line(ctx, log_group, marker_v1), requires=("wiring",))
    legs.step(
        "metrics",
        lambda: _assert_metric_filter_datapoint(ctx, namespace, metric_name, legs),
        requires=("logs",),
    )
    # The ALB's own periodic health-check requests keep the metric filter's DefaultValue publishing
    # zero datapoints, which decays an ALARM state back to OK within a couple of periods -- the alarm
    # leg has to observe it before a later, slow leg (update) lets that decay happen unobserved.
    legs.step("alarm", lambda: _assert_alarm_leaves_insufficient_data(ctx, alarm_name, legs), requires=("metrics",))
    legs.step(
        "update",
        lambda: _assert_update_replaces_task_not_service(ctx, parent, params, outputs, marker_v2, log_group, state),
        requires=("wiring",),
    )
    legs.step(
        "drift",
        lambda: _assert_parent_is_blind_to_child_drift(ctx, parent, log_group, state),
        requires=("update",),
    )
    legs.step("rollback", lambda: _assert_child_failure_rolls_parent_back(ctx, rollback))
    legs.step(
        "teardown",
        lambda: _assert_teardown_removes_children(
            ctx, parent, outputs, cluster_name, service_name, repo_name, log_group, tg_name, state
        ),
    )
    legs.verdict()


_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to one line, so evidence cannot displace the summary as the detail's last line."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised once at the end."""

    def __init__(self, ctx, total: int) -> None:
        self._ctx = ctx
        self._total = total
        self._rows: list[tuple[str, str, str]] = []
        #: Legs that FAILED. Drives the final raise.
        self._failed: set[str] = set()
        #: Legs that did not PASS (failed or blocked). Drives `requires` gating, so a leg whose
        #: prerequisite was BLOCKED is blocked too rather than run against state never produced.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a run killed by the budget still leaves a trail.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED when an immediate prerequisite did not pass.

        BLOCKED, not FAIL, so one broken hop is not counted again for every downstream leg.
        """
        blocked_by = [r for r in requires if r in self._not_passed]
        if blocked_by:
            self._not_passed.add(name)
            self._record(name, "BLOCKED", f"requires {','.join(blocked_by)}")
            return None
        try:
            evidence = fn()
        except AssertionError:
            raise
        except BaseException as exc:  # noqa: BLE001 -- recorded, then re-raised in aggregate
            self._failed.add(name)
            self._not_passed.add(name)
            self._record(name, "FAIL", _one_line(exc))
            return None
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def hard(self, name: str, fn):
        """A leg with nothing gradeable downstream (deploy, bootstrap): raise immediately."""
        try:
            evidence = fn()
        except AssertionError:
            raise
        except BaseException as exc:  # noqa: BLE001
            self._record(name, "FAIL", _one_line(exc))
            raise AssertionError(self._summary(name, _one_line(exc))) from exc
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def never_reached(self, what: str, waited_s: float):
        """Fail for a state the target accepted and never reached."""
        raise AssertionError(f"{what}; not reached after {waited_s:.0f}s of polling")

    def _summary(self, headline_leg: str, headline_evidence: str) -> str:
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        cells = " ".join(f"{n}={v}" for n, v, _ in self._rows)
        # The cells are truncated, NEVER the headline: the headline is the only thing _err_line
        # keeps, so it must survive intact.
        head = _one_line(f"WORKFLOW FAILED at {headline_leg}: {headline_evidence}", _HEADLINE_CAP)
        return f"LEGS {n_pass}/{self._total} PASS | {cells[:900]}\n{head}"

    def verdict(self) -> None:
        """Raise once if any leg failed. Call as the LAST statement of run()."""
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        print(f"[legs] {n_pass}/{self._total} PASS", flush=True)
        if not self._failed:
            return
        leg, _, evidence = next(r for r in self._rows if r[1] == "FAIL")
        raise AssertionError(self._summary(leg, evidence))


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=1200,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    _record_stack_id = _task_definition_teardown(ctx, name)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    ctx.on_cleanup(_record_stack_id)
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _start_stack_raw(ctx, template, *, parameters) -> str:
    """create_stack with _deploy_cfn's tagging and cleanup registration, without waiting.

    The failure-injection leg needs the failed status and the events, which _deploy_cfn discards by
    raising.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )
    _record_stack_id_2 = _task_definition_teardown(ctx, name)
    ctx.on_cleanup(lambda: _delete_stack_deadline(ctx, name, timeout_s=900.0))
    ctx.on_cleanup(_record_stack_id_2)
    return name


def _wait_create_terminal(ctx, name, *, timeout_s) -> str:
    """Wait for a create-terminal state, WITHOUT asserting success."""
    cfn = ctx.client("cloudformation")
    return _poll_until(
        lambda: _stack_status(cfn, name),
        lambda s: s in _CREATE_TERMINAL,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"CFN stack {name} reached a create-terminal state",
    )


def _swallow(fn):
    """Run fn(), tolerating only the not-found answers NoSuchBucket and ResourceNotFoundException."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "ResourceNotFoundException"):
            raise


def _stack_status(cfn, name: str) -> str:
    """The stack's status, or "GONE" when DescribeStacks answers that it does not exist."""
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationError" and err.get("Message") == f"Stack with id {name} does not exist":
            return "GONE"
        raise


def _delete_stack_deadline(ctx, name: str, *, timeout_s: float) -> None:
    """delete_stack, then wait up to timeout_s (longer than the 120s of _delete_stack_and_wait), raising
    on DELETE_FAILED or any error but not-found. A parent whose children hold an ALB, an ECS service and
    a security group needs many minutes: the load balancer's ENIs keep the group referenced."""
    cfn = ctx.client("cloudformation")
    try:
        if _stack_status(cfn, name) == "GONE":
            return
        cfn.delete_stack(StackName=name)
        final = _poll_until(
            lambda: _stack_status(cfn, name),
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=timeout_s,
            interval_s=2.0,
            description=f"delete stack {name}",
        )
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {name} ended DELETE_FAILED — its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _expect_error(fn, code: str, message: str, what: str) -> str:
    """Assert the call is refused with exactly this code and message; a success raises."""
    try:
        fn()
    except ClientError as exc:
        got_code = _error_code(exc)
        got_message = exc.response.get("Error", {}).get("Message", "")
        assert got_code == code, f"{what}: expected {code}, got {got_code}: {got_message!r}"
        assert got_message == message, f"{what}: expected message {message!r}, got {got_message!r}"
        return got_code
    raise AssertionError(f"{what}: the call SUCCEEDED; expected {code}")


def _utc(epoch: float):
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)


def _delete_when_free(fn, timeout_s=600.0, interval_s=2.0):
    """Teardown: retry a VPC-scoped delete while AWS still reports a dependency. Fargate task and
    load-balancer ENIs are released asynchronously after their owners are deleted."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("DependencyViolation", "ResourceInUse") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _ec2_tags(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name},
                                                      {"Key": "sim2real:managed", "Value": "true"}]}]


def _owned_vpc(ctx, ec2, cidr):
    """A VPC the check creates: two public subnets in two AZs, routed to an internet gateway."""
    import ipaddress

    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_ec2_tags("vpc", _xname(ctx, "vpc")))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_when_free(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc_id], WaiterConfig={"Delay": 1, "MaxAttempts": 60}
    )
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_ec2_tags("internet-gateway", _xname(ctx, "igw")))[
        "InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_when_free(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))
    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_ec2_tags("route-table", _xname(ctx, "rtb")))[
        "RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_id))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"an ALB needs two availability zones; {ctx.region} offers {zones!r}"
    halves = list(ipaddress.ip_network(cidr).subnets(prefixlen_diff=1))
    subnet_ids = []
    for zone, block in zip(zones[:2], halves):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=str(block), AvailabilityZone=zone,
            TagSpecifications=_ec2_tags("subnet", _xname(ctx, "subnet")))["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _delete_when_free(lambda: ec2.delete_subnet(SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc_id: ec2.disassociate_route_table(AssociationId=a))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _prefix_list_state(ec2, pl_id: str) -> str:
    try:
        return ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"]
    except ClientError as exc:
        if _error_code(exc) == "InvalidPrefixListID.NotFound":
            return "GONE"
        raise


def _delete_prefix_list_and_wait(ec2, pl_id: str) -> None:
    """Delete the ingress prefix list, then confirm it actually left -- a delete call that returns
    without error is not proof of effect (DeleteManagedPrefixList can accept the request and still
    leave the list in a non-terminal state)."""
    try:
        _delete_when_free(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))
    except ClientError as exc:
        if _error_code(exc) != "InvalidPrefixListID.NotFound":
            raise
    _poll_until(
        lambda: _prefix_list_state(ec2, pl_id),
        lambda s: s in {"delete-complete", "GONE"},
        timeout_s=120.0, interval_s=2.0,
        description=f"prefix list {pl_id} deleted",
    )


def _ingress_prefix_list(ctx, ec2) -> str:
    """A managed prefix list of ctx.ingress_cidrs(), the only source the ALB's group admits on tcp/80."""
    cidrs = ctx.ingress_cidrs()
    pl_id = ec2.create_managed_prefix_list(
        PrefixListName=_xname(ctx, "ingress"), AddressFamily="IPv4", MaxEntries=len(cidrs),
        Entries=[{"Cidr": c} for c in cidrs],
        TagSpecifications=_ec2_tags("prefix-list", _xname(ctx, "ingress")),
    )["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: _delete_prefix_list_and_wait(ec2, pl_id))
    _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"],
        lambda state: state != "create-in-progress",
        timeout_s=120.0, interval_s=2.0, description=f"prefix list {pl_id} created",
    )
    return pl_id


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if _error_code(exc) not in {"NoSuchBucket", "AccessDenied"}:
            raise RuntimeError(f"emptying {bucket} failed: {exc}") from exc


def _upload_child_templates(ctx) -> dict[str, str]:
    """Create a bucket, upload every child template, return {filename: TemplateURL}.

    A nested stack's TemplateURL must be an S3 URL; no bootstrap bucket is assumed.
    """
    s3 = ctx.client("s3")
    bucket = _xname(ctx, "tpl")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is the one region CreateBucket rejects a matching LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _swallow(lambda: s3.delete_bucket(Bucket=bucket)))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))
    urls: dict[str, str] = {}
    for name in (_NETWORK, _SERVICE, _OBSERVABILITY, _INVALID_CHILD):
        s3.put_object(
            Bucket=bucket,
            Key=name,
            Body=(DEPLOYMENTS / name).read_bytes(),
            ContentType="text/yaml",
        )
        urls[name] = ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{name}", bucket, name)
    return urls


def _stack(ctx, name_or_id: str) -> dict:
    return ctx.client("cloudformation").describe_stacks(StackName=name_or_id)["Stacks"][0]


def _child_stack_id(ctx, parent: str, logical: str) -> str:
    detail = ctx.client("cloudformation").describe_stack_resource(
        StackName=parent, LogicalResourceId=logical
    )["StackResourceDetail"]
    assert detail["ResourceType"] == "AWS::CloudFormation::Stack", (
        f"{logical} is {detail['ResourceType']!r}, not a nested stack"
    )
    return detail["PhysicalResourceId"]


def _physical_ids(ctx, stack_name: str) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    out: dict[str, str] = {}
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stack_resources(**kwargs)
        for r in page["StackResourceSummaries"]:
            out[r["LogicalResourceId"]] = r.get("PhysicalResourceId", "")
        token = page.get("NextToken")
        if not token:
            return out


def _stack_events(ctx, stack_name_or_id: str) -> list[dict]:
    cfn = ctx.client("cloudformation")
    out: list[dict] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack_name_or_id}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        out.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token or len(out) >= 1000:
            return out


def _stack_parameters(ctx, stack_name_or_id: str) -> dict[str, str]:
    return {
        p["ParameterKey"]: p["ParameterValue"]
        for p in _stack(ctx, stack_name_or_id).get("Parameters", [])
    }


def _stack_outputs(ctx, stack_name_or_id: str) -> dict[str, str]:
    return {
        o["OutputKey"]: o["OutputValue"] for o in _stack(ctx, stack_name_or_id).get("Outputs", [])
    }


def _resource_drifts(ctx, stack: str) -> list[dict]:
    cfn = ctx.client("cloudformation")
    out: list[dict] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kwargs)
        out.extend(page.get("StackResourceDrifts", []))
        token = page.get("NextToken")
        if not token:
            return out


def _detect_drift(ctx, stack: str, *, timeout_s=900.0) -> dict:
    cfn = ctx.client("cloudformation")
    detection_id = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    detection = _poll_until(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id),
        lambda d: d["DetectionStatus"] != "DETECTION_IN_PROGRESS",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"drift detection for {stack}",
    )
    assert detection["DetectionStatus"] == "DETECTION_COMPLETE", (
        f"drift detection did not complete: {detection!r}"
    )
    return detection


def _load_balancer_url(ctx, outputs) -> str:
    """The root URL of the load balancer the stack published, dialed as published."""
    return ctx.endpoint_url("http://" + outputs["LoadBalancerDns"]) + "/"


def _http_get(url: str, timeout_s: float = 15.0):
    """(status, body) for a plain GET. An HTTP error STATUS is returned, not raised, so a 503 from the
    load balancer is an observation; a transport failure returns (None, reason)."""
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-xsvc"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _log_messages(ctx, group: str) -> list[str]:
    logs = ctx.client("logs")
    out: list[str] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"logGroupName": group, "limit": 200}
        if token:
            kwargs["nextToken"] = token
        try:
            page = logs.filter_log_events(**kwargs)
        except ClientError:
            return out
        out.extend(e.get("message", "") for e in page.get("events", []))
        token = page.get("nextToken")
        if not token or len(out) >= 2000:
            return out


def _json_lines(messages: list[str]) -> list[dict]:
    parsed = []
    for m in messages:
        text = m.strip()
        if not text.startswith("{"):
            continue
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(doc, dict):
            parsed.append(doc)
    return parsed


def _log_group_exists(ctx, name: str) -> bool:
    groups = ctx.client("logs").describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
    return any(g["logGroupName"] == name for g in groups)


def _target_health(ctx, tg_arn: str) -> dict[str, str]:
    resp = ctx.client("elbv2").describe_target_health(TargetGroupArn=tg_arn)
    return {
        d["Target"]["Id"]: d["TargetHealth"]["State"] for d in resp["TargetHealthDescriptions"]
    }


# ---- legs ----------------------------------------------------------------------------------------


def _assert_children_are_real_stacks(ctx, parent, repo_name, state) -> str:
    """Each AWS::CloudFormation::Stack resource is a STACK of its own -- CREATE_COMPLETE, with ParentId
    and RootId pointing back here -- and each child's own resources exist."""
    parent_id = _stack(ctx, parent)["StackId"]
    children = {}
    for logical in ("NetworkStack", "ObservabilityStack", "ServiceStack"):
        child_id = _child_stack_id(ctx, parent, logical)
        children[logical] = child_id
        child = _stack(ctx, child_id)
        assert child["StackStatus"] == "CREATE_COMPLETE", (logical, child["StackStatus"])
        assert child.get("ParentId") == parent_id, (
            f"{logical} reports ParentId {child.get('ParentId')!r}; a nested stack must name its "
            f"parent ({parent_id})"
        )
        assert child.get("RootId") == parent_id, (
            f"{logical} reports RootId {child.get('RootId')!r}, expected {parent_id}"
        )
    state["children"] = children

    net = {r for r in _physical_ids(ctx, children["NetworkStack"])}
    assert {"IngressGroup", "ServiceTargets", "PlatformBalancer", "PlatformListener"} <= net, net
    obs = {r for r in _physical_ids(ctx, children["ObservabilityStack"])}
    assert {"PlatformLogGroup", "StartedFilter", "StartedAlarm"} <= obs, obs
    svc_ids = _physical_ids(ctx, children["ServiceStack"])
    assert {"ImageRepository", "PlatformCluster", "PlatformTask", "PlatformService"} <= set(svc_ids), svc_ids
    state["service_ids_v1"] = svc_ids

    # The ECR repository the service child declared, read through ECR itself.
    ecr = ctx.client("ecr")
    repo = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]
    assert repo["imageScanningConfiguration"]["scanOnPush"] is True, repo
    # repositoryUri is <registryId>.dkr.ecr.<region>.<domain>/<name>; the domain is the target's.
    host, _, path = repo["repositoryUri"].partition("/")
    labels = host.split(".")
    assert (labels[:4] == [repo["registryId"], "dkr", "ecr", ctx.region] and len(labels) > 4
            and all(labels[4:]) and path == repo_name), (repo["repositoryUri"], repo_name)
    lifecycle = ecr.get_lifecycle_policy(repositoryName=repo_name)["lifecyclePolicyText"]
    assert "expire" in lifecycle and "untagged" in lifecycle, lifecycle
    return f"3 child stacks CREATE_COMPLETE under {parent_id.rsplit('/', 2)[-2]}"


def _assert_cross_stack_references_resolved(ctx, parent, outputs, log_group, state) -> str:
    """The values the service child received are BYTE-IDENTICAL to the outputs its siblings produced,
    and the parent's outputs are those same child values -- the Fn::GetAtt hops, checked at both ends."""
    children = state["children"]
    net_out = _stack_outputs(ctx, children["NetworkStack"])
    obs_out = _stack_outputs(ctx, children["ObservabilityStack"])
    svc_params = _stack_parameters(ctx, children["ServiceStack"])

    assert svc_params["TargetGroupArn"] == net_out["TargetGroupArn"], (
        f"the service child received TargetGroupArn {svc_params['TargetGroupArn']!r}; the network "
        f"child produced {net_out['TargetGroupArn']!r}"
    )
    assert svc_params["SecurityGroupId"] == net_out["SecurityGroupId"], svc_params
    assert svc_params["LogGroupNameFromObservability"] == obs_out["LogGroupNameOut"] == log_group, (
        f"the service child received log group {svc_params['LogGroupNameFromObservability']!r}; the "
        f"observability child produced {obs_out['LogGroupNameOut']!r}"
    )
    for key, value in (
        ("TargetGroupArn", net_out["TargetGroupArn"]),
        ("LoadBalancerDns", net_out["LoadBalancerDns"]),
        ("LogGroupNameOut", obs_out["LogGroupNameOut"]),
        ("AlarmNameOut", obs_out["AlarmNameOut"]),
    ):
        assert outputs[key] == value, (
            f"the parent's {key} output is {outputs[key]!r}, the child produced {value!r}"
        )

    # The reference had to reach the task definition, not just the stack parameter.
    task = ctx.client("ecs").describe_task_definition(taskDefinition=outputs["TaskDefinitionArn"])[
        "taskDefinition"
    ]
    options = task["containerDefinitions"][0]["logConfiguration"]["options"]
    assert options["awslogs-group"] == log_group, options
    assert options["awslogs-region"] == ctx.region, options
    return f"tg/sg/log-group resolved child->parent->child, awslogs-group={log_group}"


def _assert_platform_serves_http(ctx, outputs, cluster_name, marker) -> str:
    """A real request through the load balancer is answered by the Fargate task's own process, and the
    task's awsvpc address is what the target group registered."""
    ecs = ctx.client("ecs")
    service = _poll_until(
        lambda: ecs.describe_services(cluster=cluster_name, services=[outputs["ServiceNameOut"]])[
            "services"
        ][0],
        lambda s: s["runningCount"] == s["desiredCount"] and s["desiredCount"] >= 1,
        timeout_s=600.0,
        interval_s=2.0,
        description=f"service {outputs['ServiceNameOut']} runningCount == desiredCount",
    )
    assert service["status"] == "ACTIVE", service["status"]
    health = _poll_until(
        lambda: _target_health(ctx, outputs["TargetGroupArn"]),
        lambda h: any(v == "healthy" for v in h.values()),
        timeout_s=600.0,
        interval_s=2.0,
        description=f"a healthy target in {outputs['TargetGroupArn']}",
    )
    url = _load_balancer_url(ctx, outputs)
    status, body = _poll_until(
        lambda: _http_get(url),
        lambda r: r[0] == 200,
        timeout_s=420.0,
        interval_s=2.0,
        description=f"HTTP 200 through the load balancer at {url}",
    )
    assert marker in body, (
        f"the load balancer answered 200 but not with the container's body: {body[:200]!r}"
    )
    return f"GET / -> 200 carrying {marker}, {sum(1 for v in health.values() if v == 'healthy')} healthy"


def _assert_structured_line(ctx, log_group: str, marker: str) -> str:
    """The container's stdout reached the log group a DIFFERENT child stack created, as the JSON line
    the metric filter keys on."""
    assert _log_group_exists(ctx, log_group), f"log group {log_group} does not exist"
    docs = _poll_until(
        lambda: [
            d
            for d in _json_lines(_log_messages(ctx, log_group))
            if d.get("event") == "service.started" and d.get("marker") == marker
        ],
        lambda ds: bool(ds),
        timeout_s=420.0,
        interval_s=2.0,
        description=f"service.started line for {marker}",
    )
    assert docs[0].get("host"), f"the structured line carries no container hostname: {docs[0]!r}"
    return f"service.started marker={marker} host={docs[0]['host']}"


def _assert_metric_filter_datapoint(ctx, namespace, metric_name, legs) -> str:
    """The observability child's metric filter turns the container's line into a real datapoint."""
    started = time.monotonic()
    deadline = 420.0
    total = 0.0
    while time.monotonic() - started < deadline:
        now = time.time()
        points = ctx.client("cloudwatch").get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=_utc(now - 1800),
            EndTime=_utc(now + 120),
            Period=60,
            Statistics=["Sum"],
        )["Datapoints"]
        total = sum(p["Sum"] for p in points)
        if total >= 1:
            return f"{namespace}/{metric_name} Sum={total}"
        time.sleep(2)
    legs.never_reached(
        f"metric filter never produced a datapoint for {namespace}/{metric_name}",
        time.monotonic() - started,
    )
    return ""


def _assert_alarm_leaves_insufficient_data(ctx, alarm_name: str, legs) -> str:
    """The alarm a third child declared crosses INSUFFICIENT_DATA -> ALARM off that metric, read from
    CloudWatch's own history rather than from the current state."""
    cw = ctx.client("cloudwatch")
    started = time.monotonic()
    deadline = 480.0
    current = None
    while time.monotonic() - started < deadline:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
        assert alarms, f"alarm {alarm_name} does not exist"
        current = alarms[0]["StateValue"]
        if current == "ALARM":
            break
        time.sleep(2)
    if current != "ALARM":
        legs.never_reached(
            f"alarm {alarm_name} stayed in {current!r} although the metric filter reported a match",
            time.monotonic() - started,
        )
    items = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=100
    )["AlarmHistoryItems"]
    assert items, f"no StateUpdate history for {alarm_name}"
    pairs = []
    for item in reversed(items):
        try:
            data = json.loads(item["HistoryData"])
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
        pairs.append(
            (
                (data.get("oldState") or {}).get("stateValue"),
                (data.get("newState") or {}).get("stateValue"),
            )
        )
    assert pairs and pairs[0][0] == "INSUFFICIENT_DATA", (
        f"the alarm's first transition must come out of INSUFFICIENT_DATA: {pairs}"
    )
    assert any(new == "ALARM" for _, new in pairs), pairs
    return f"INSUFFICIENT_DATA->ALARM ({len(pairs)} transition(s))"


def _assert_update_replaces_task_not_service(ctx, parent, params, outputs, marker_v2, log_group, state) -> str:
    """A parent update replaces the TaskDefinition, modifies the Service and child stacks in place,
    and the load balancer then serves the new marker.
    """
    cfn = ctx.client("cloudformation")
    children_before = dict(state["children"])
    svc_before = state["service_ids_v1"]
    cfn.update_stack(
        StackName=parent,
        TemplateBody=(DEPLOYMENTS / _PARENT).read_text(),
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v}
            for k, v in dict(params, Marker=marker_v2, RetentionDays="14").items()
        ],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    final = _poll_until(
        lambda: _stack_status(cfn, parent),
        lambda s: s in _UPDATE_TERMINAL,
        timeout_s=1800.0,
        interval_s=2.0,
        description=f"update parent stack {parent}",
    )
    assert final == "UPDATE_COMPLETE", f"the parent update ended {final!r}"

    for logical, child_id in children_before.items():
        after_id = _child_stack_id(ctx, parent, logical)
        assert after_id == child_id, (
            f"{logical} was REPLACED by the update ({child_id} -> {after_id}); a parameter change to "
            "a nested stack is an update, not a recreation"
        )
    svc_after = _physical_ids(ctx, children_before["ServiceStack"])
    assert svc_after["PlatformTask"] != svc_before["PlatformTask"], (
        "the container command changed, so the task definition must be a NEW revision; it kept "
        f"{svc_before['PlatformTask']!r}"
    )
    assert svc_after["PlatformTask"].rsplit(":", 1)[0] == svc_before["PlatformTask"].rsplit(":", 1)[0], (
        f"the replacement revision must stay in the same family: {svc_before['PlatformTask']!r} -> "
        f"{svc_after['PlatformTask']!r}"
    )
    assert int(svc_after["PlatformTask"].rsplit(":", 1)[1]) > int(
        svc_before["PlatformTask"].rsplit(":", 1)[1]
    ), (svc_before["PlatformTask"], svc_after["PlatformTask"])
    assert svc_after["PlatformService"] == svc_before["PlatformService"], (
        "the ECS service was replaced by an in-place property change: "
        f"{svc_before['PlatformService']!r} -> {svc_after['PlatformService']!r}"
    )
    state["service_ids_v2"] = svc_after

    groups = [
        g
        for g in ctx.client("logs").describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
        if g["logGroupName"] == log_group
    ]
    assert groups and groups[0].get("retentionInDays") == 14, groups

    url = _load_balancer_url(ctx, outputs)
    status, body = _poll_until(
        lambda: _http_get(url),
        lambda r: r[0] == 200 and marker_v2 in (r[1] or ""),
        timeout_s=600.0,
        interval_s=2.0,
        description=f"the load balancer serves the new marker {marker_v2}",
    )
    assert status == 200, (status, body[:200])
    return "task def replaced (new revision), service + child stacks modified, new marker served"


def _assert_parent_is_blind_to_child_drift(ctx, parent, log_group, state) -> str:
    """Parent drift results omit nested stacks (not drift-supported) and the parent is not DRIFTED,
    while drift detection on the child reports the mutated log group MODIFIED.
    """
    ctx.client("logs").put_retention_policy(logGroupName=log_group, retentionInDays=30)

    parent_detection = _detect_drift(ctx, parent)
    parent_drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(ctx, parent)}
    for logical in ("NetworkStack", "ObservabilityStack", "ServiceStack"):
        assert logical not in parent_drifts, (
            f"{logical} appeared in the parent's per-resource drift results ({parent_drifts[logical]!r}); "
            "AWS::CloudFormation::Stack does not support drift detection, and DescribeStackResourceDrifts "
            "excludes a resource it has not checked entirely -- it must not appear at all, NOT_CHECKED "
            "or otherwise"
        )
    assert not parent_drifts, (
        f"the parent stack has no resource that supports drift detection, so its per-resource drift "
        f"list must be empty, not {parent_drifts}"
    )
    assert parent_detection["StackDriftStatus"] == "IN_SYNC", (
        "the parent has zero drift-checkable resources of its own, so with none DRIFTED it must report "
        f"IN_SYNC -- never DRIFTED for a change made only in a child: {parent_detection!r}"
    )

    child_id = state["children"]["ObservabilityStack"]
    child_detection = _detect_drift(ctx, child_id)
    child_drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(ctx, child_id)}
    group = child_drifts.get("PlatformLogGroup")
    assert group, f"the child's drift report omits PlatformLogGroup: {sorted(child_drifts)}"
    assert group["StackResourceDriftStatus"] == "MODIFIED", (
        f"detection run on the child itself must find the out-of-band write: {group!r}"
    )
    diffs = [
        d
        for d in (group.get("PropertyDifferences") or [])
        if d.get("PropertyPath", "").endswith("/RetentionInDays")
    ]
    assert diffs, f"no PropertyDifference for /RetentionInDays: {group.get('PropertyDifferences')!r}"
    assert str(diffs[0]["ExpectedValue"]) == "14", diffs[0]
    assert str(diffs[0]["ActualValue"]) == "30", diffs[0]
    alarm = child_drifts.get("StartedAlarm")
    assert alarm and alarm["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the untouched alarm must stay IN_SYNC, got {alarm!r}"
    )
    assert child_detection["StackDriftStatus"] == "DRIFTED", child_detection
    return (
        f"parent: 0 resource-drift entries (StackDriftStatus={parent_detection['StackDriftStatus']!r}); "
        "child: PlatformLogGroup MODIFIED 14->30"
    )


def _start_rollback_parent(ctx, urls, namespace) -> dict:
    """Create the failure-injection parent; a refused create is kept for the rollback leg to report."""
    log_group = _xname(ctx, "rblg")
    alarm_name = _xname(ctx, "rbalarm")
    metric_name = "RollbackProbe" + ctx.unique_name("")[:10]
    ctx.on_cleanup(
        lambda: _swallow(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))
    )
    started: dict[str, Any] = {"log_group": log_group, "alarm_name": alarm_name}
    try:
        started["name"] = _start_stack_raw(
            ctx,
            (DEPLOYMENTS / _ROLLBACK_PARENT).read_text(),
            parameters={
                "ObservabilityTemplateUrl": urls[_OBSERVABILITY],
                "FailingTemplateUrl": urls[_INVALID_CHILD],
                "LogGroupName": log_group,
                "RetentionDays": "7",
                "MetricNamespace": namespace,
                "MetricName": metric_name,
                "AlarmName": alarm_name,
                "BadRetentionDays": _BAD_RETENTION,
            },
        )
    except Exception as exc:  # noqa: BLE001 - graded by the rollback leg, not the deploy
        started["error"] = exc
    return started


def _assert_child_failure_rolls_parent_back(ctx, started) -> str:
    """A resource CloudWatch Logs refuses inside one child rolls the whole parent back, the denial is
    named in parent and child events, and the successful sibling's resources are gone.
    """
    if "error" in started:
        raise started["error"]
    log_group, alarm_name, name = started["log_group"], started["alarm_name"], started["name"]
    status = _wait_create_terminal(ctx, name, timeout_s=900.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"a child that cannot be created must roll the parent back; the parent ended {status!r}"
    )

    events = _stack_events(ctx, name)
    failed = [
        e
        for e in events
        if e["LogicalResourceId"] == "FailingStack" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert failed, (
        "the parent records no CREATE_FAILED for the nested stack: "
        f"{sorted({e['LogicalResourceId'] + ':' + e['ResourceStatus'] for e in events})}"
    )
    child_id = failed[0].get("PhysicalResourceId", "")
    assert child_id, f"the failed nested stack has no physical id: {failed[0]!r}"
    reason = failed[0].get("ResourceStatusReason", "")
    expected_reason = (
        f"Embedded stack {child_id} was not successfully created: "
        "The following resource(s) failed to create: [Rejected]. "
    )
    assert reason == expected_reason, (
        f"the parent's failure reason must name the child resource that failed: {reason!r}, "
        f"expected {expected_reason!r}"
    )

    child_events = _stack_events(ctx, child_id)
    child_failed = [
        e
        for e in child_events
        if e["LogicalResourceId"] == "Rejected" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert child_failed, (
        f"the child stack {child_id} records no CREATE_FAILED for Rejected: "
        f"{sorted({e['LogicalResourceId'] + ':' + e['ResourceStatus'] for e in child_events})}"
    )
    # The reason is 'Resource handler returned message: "<msg> (Service: <svc>, Status Code: <n>,
    # Request ID: <uuid>) (SDK Attempt Count: <n>)" (RequestToken: <uuid>, HandlerErrorCode: <code>)'.
    # The ids differ per call; the handler message, service, status and handler code do not.
    child_reason = child_failed[0].get("ResourceStatusReason", "")
    handler_message, _, rest = child_reason.partition(" (Service: ")
    expected_handler = (
        'Resource handler returned message: "Invalid retention value. Valid values are: '
        "[1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, "
        '2922, 3288, 3653]'
    )
    assert handler_message == expected_handler, (
        f"the child's failure reason must be the Logs handler's retention refusal: {child_reason!r}"
    )
    service_and_status = rest.partition(", Request ID: ")[0]
    assert service_and_status == "CloudWatchLogs, Status Code: 400", (
        f"the child's failure reason must come from CloudWatch Logs with a 400: {child_reason!r}"
    )
    handler_code = child_reason.rpartition(", HandlerErrorCode: ")[2]
    assert handler_code == "InvalidRequest)", (
        f"the Logs resource handler must classify the retention as InvalidRequest: {child_reason!r}"
    )

    # effect-absent: the sibling that SUCCEEDED was rolled back too.
    assert not _log_group_exists(ctx, log_group), (
        f"the parent rolled back but the successful child's log group {log_group} still exists"
    )
    assert not ctx.client("cloudwatch").describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"], (
        f"the parent rolled back but the successful child's alarm {alarm_name} still exists"
    )
    assert not _log_group_exists(ctx, f"{log_group}-rejected"), (
        "the log group the failing child attempted must not exist"
    )
    return "parent ROLLBACK_COMPLETE, child reason names retention, sibling log group + alarm gone"


def _assert_teardown_removes_children(
    ctx, parent, outputs, cluster_name, service_name, repo_name, log_group, tg_name, state
) -> str:
    """After delete_stack the CHILD stacks and every resource they owned are gone, and the platform
    stops serving: the load balancer's DNS name stops answering with the container's body."""
    cfn = ctx.client("cloudformation")
    children = state["children"]
    cfn.delete_stack(StackName=parent)
    final = _poll_until(
        lambda: _stack_status(cfn, parent),
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=1800.0,
        interval_s=2.0,
        description=f"delete parent stack {parent}",
    )
    assert final in {"DELETE_COMPLETE", "GONE"}, f"parent delete ended {final!r}"

    for logical, child_id in children.items():
        child_status = _stack_status(cfn, child_id)
        assert child_status in {"DELETE_COMPLETE", "GONE"}, (
            f"child {logical} is {child_status!r}; deleting the parent must cascade"
        )

    _expect_error(
        lambda: ctx.client("ecr").describe_repositories(repositoryNames=[repo_name]),
        "RepositoryNotFoundException",
        f"The repository with name '{repo_name}' does not exist in the registry with id "
        f"'{ctx.account}'",
        "the ECR repository must be gone",
    )
    clusters = ctx.client("ecs").describe_clusters(clusters=[cluster_name])["clusters"]
    assert not [c for c in clusters if c.get("status") == "ACTIVE"], (
        f"cluster {cluster_name} outlived its stack: {clusters!r}"
    )
    _expect_error(
        lambda: ctx.client("elbv2").describe_target_groups(Names=[tg_name]),
        "TargetGroupNotFound",
        "One or more target groups not found",
        "the target group must be gone",
    )
    assert not _log_group_exists(ctx, log_group), f"log group {log_group} outlived its stack"

    url = _load_balancer_url(ctx, outputs)
    status, body = _poll_until(
        lambda: _http_get(url),
        lambda r: r[0] is None or r[0] >= 500,
        timeout_s=300.0,
        interval_s=2.0,
        description="the deleted load balancer stops serving the container's body",
    )
    assert status is None or status >= 500, (status, (body or "")[:120])
    return f"parent {final}, 3 children gone, repo/cluster/tg/log-group gone, LB answers {status!r}"


def _task_definition_teardown(ctx, stack_name: str):
    """Delete the stack's task definition revisions once it is deleted (CloudFormation only
    deregisters them). Returns a callback that stores the stack id; register it after the stack's deletion."""
    state: dict = {}
    ctx.on_cleanup(lambda: _delete_stack_task_definitions(ctx, state.get("stack_id")))

    def _record_stack_id() -> None:
        try:
            state["stack_id"] = ctx.client("cloudformation").describe_stacks(
                StackName=stack_name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise

    return _record_stack_id


def _delete_stack_task_definitions(ctx, stack_id) -> None:
    """Wait for the stack's deletion, then delete each task definition revision it registered."""
    if stack_id is None:
        return
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    arns, pending, seen = set(), [stack_id], set()
    while pending:
        sid = pending.pop()
        if sid in seen:
            continue
        seen.add(sid)
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=sid):
            for event in page["StackEvents"]:
                physical = event.get("PhysicalResourceId") or ""
                if not physical.startswith("arn:") or event["ResourceStatus"] not in (
                        "CREATE_COMPLETE", "UPDATE_COMPLETE"):
                    continue
                if event["ResourceType"] == "AWS::ECS::TaskDefinition":
                    arns.add(physical)
                elif event["ResourceType"] == "AWS::CloudFormation::Stack" and physical != sid:
                    pending.append(physical)
    for arn in sorted(arns):
        try:
            status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        except ClientError as exc:
            if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
                continue
            raise
        if status == "DELETE_IN_PROGRESS":
            continue
        if status == "ACTIVE":
            ecs.deregister_task_definition(taskDefinition=arn)
        failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
        if failures:
            raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
