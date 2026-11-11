"""container-lifecycle-ecr-ecs-service-logs."""

from __future__ import annotations

import base64
import json
import subprocess
import time
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing, require_tools

CHECK = "container-lifecycle-ecr-ecs-service-logs"
GROUP = "service-lifecycle"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]

#: A public busybox image, pre-seeded on the runner and retagged into ECR. The check never pulls it,
#: so no run egresses to a public registry.
_SOURCE_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_CONTAINER = "app"
_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-ctr"}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """An image pushed to ECR runs as a Fargate ECS service: the running task pulled exactly that
    digest, the service reaches a COMPLETED rollout with one running task, and the container's
    stdout lands in its awslogs stream. Then every resource is torn down and proven gone."""
    require_tools("docker")
    ecs, ecr, logs = ctx.client("ecs"), ctx.client("ecr"), ctx.client("logs")
    marker = ctx.unique_name("sim2real-marker-")
    repo = ctx.unique_name("sim2real-ctr-repo-")
    log_group = "/sim2real/" + ctx.unique_name("ctr-")
    cluster = ctx.unique_name("sim2real-ctr-cluster-")
    role = ctx.unique_name("sim2real-ctr-exec-")
    family = ctx.unique_name("sim2real-ctr-td-")
    service = ctx.unique_name("sim2real-ctr-svc-")

    # --- build: ECR repository + pushed image -------------------------------------------------
    repo_uri = ecr.create_repository(repositoryName=repo, tags=_kv(_MANAGED_TAGS))["repository"][
        "repositoryUri"
    ]
    ctx.on_cleanup(
        _tolerant(lambda: ecr.delete_repository(repositoryName=repo, force=True),
                  "RepositoryNotFoundException")
    )
    _push_image(ctx, ecr, repo_uri, "v1")
    pushed = ecr.describe_images(repositoryName=repo, imageIds=[{"imageTag": "v1"}])["imageDetails"]
    assert len(pushed) == 1 and str(pushed[0].get("imageDigest", "")).startswith("sha256:"), (
        f"DescribeImages(v1) after the push returned {pushed!r}, expected one image with a digest"
    )
    digest = pushed[0]["imageDigest"]

    # --- deploy: log group, execution role, cluster, task definition, service --------------------
    logs.create_log_group(logGroupName=log_group, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(
        _tolerant(lambda: logs.delete_log_group(logGroupName=log_group), "ResourceNotFoundException")
    )
    role_arn = _create_execution_role(ctx, role)
    net = _create_network(ctx)
    ecs.create_cluster(clusterName=cluster, tags=_ecs_kv())
    ctx.on_cleanup(_tolerant(lambda: ecs.delete_cluster(cluster=cluster), "ClusterNotFoundException"))
    td_arn = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        containerDefinitions=[
            {
                "name": _CONTAINER,
                "image": f"{repo_uri}:v1",
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}; sleep 3600"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "ecs",
                    },
                },
            }
        ],
        tags=_ecs_kv(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(_tolerant(lambda: ecs.deregister_task_definition(taskDefinition=td_arn),
                             "ClientException"))
    ecs.create_service(
        cluster=cluster,
        serviceName=service,
        taskDefinition=td_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [net["subnet_id"]],
                "securityGroups": [net["sg_id"]],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=_ecs_kv(),
    )
    ctx.on_cleanup(_tolerant(lambda: _force_delete_service(ecs, cluster, service),
                             "ServiceNotFoundException", "ClusterNotFoundException",
                             "ServiceNotActiveException"))

    # --- steady state: the rollout COMPLETES with one task running the pushed digest -------------
    svc = _poll(
        ctx,
        lambda: ecs.describe_services(cluster=cluster, services=[service])["services"][0],
        lambda s: _rollout(s) in ("COMPLETED", "FAILED") and s.get("runningCount") == 1,
        f"service {service} reaches a terminal rollout with one running task",
    )
    assert _rollout(svc) == "COMPLETED", f"service rollout ended {_rollout(svc)!r}: {svc.get('events', [])[:3]!r}"
    assert (svc["runningCount"], svc["desiredCount"]) == (1, 1), (
        f"runningCount/desiredCount {svc['runningCount']}/{svc['desiredCount']}, expected 1/1"
    )
    task_arns = ecs.list_tasks(cluster=cluster, serviceName=service, desiredStatus="RUNNING")["taskArns"]
    assert len(task_arns) == 1, f"ListTasks(service, RUNNING) returned {task_arns!r}, expected one task"
    task = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"][0]
    assert task["lastStatus"] == "RUNNING", f"the service's task is {task['lastStatus']!r}, not RUNNING"
    got_digest = task["containers"][0].get("imageDigest")
    assert got_digest == digest, (
        f"the running container reports imageDigest {got_digest!r}; ECR holds {digest!r} for the "
        f"pushed tag, so the task did not run the image pulled from ECR"
    )

    # --- observe: the container's stdout reached its awslogs stream ----------------------------
    task_id = task_arns[0].rsplit("/", 1)[-1]
    stream = f"ecs/{_CONTAINER}/{task_id}"
    messages = _poll(
        ctx,
        lambda: _stream_messages(logs, log_group, stream),
        lambda ms: any(marker in m for m in ms),
        f"marker in log stream {stream}",
    )
    assert any(marker in m for m in messages), f"marker absent from {stream}: {messages[:5]!r}"

    # --- tear down in reverse dependency order and prove each resource gone ---------------------
    _gone_service(ctx, cluster, service, task_arns[0])
    _gone_cluster(ctx, cluster, td_arn, net)
    _gone_task_definition(ctx, td_arn, family)
    _gone_repository(ctx, repo)
    _gone_log_group(ctx, log_group)
    _gone_role(ctx, role)
    _gone_network(ctx, net)


def _kv(d: dict) -> list[dict]:
    return [{"Key": k, "Value": v} for k, v in d.items()]


def _ecs_kv() -> list[dict]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, what: str, timeout_s: float | None = None):
    """Poll ``probe`` until ``done`` holds; raise on the bounded deadline."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s or _GONE_S * 2)
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what}: not reached; last observed {str(last)[:200]}")
        time.sleep(_POLL_S)


def _rollout(svc: dict) -> str | None:
    primary = [d for d in svc.get("deployments", []) if d.get("status") == "PRIMARY"]
    return primary[0].get("rolloutState") if primary else None


def _stream_messages(logs, group: str, stream: str) -> list[str]:
    try:
        events = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    except ClientError as exc:
        if _err(exc)[0] == "ResourceNotFoundException":
            return []
        raise
    return [e["message"] for e in events["events"]]


#: docker stderr fragments meaning no registry answered (refused, unresolvable, timed out, absent).
_UNREACHABLE = ("connection refused", "no such host", "i/o timeout", "Client.Timeout", "404 Not Found")


def _push_image(ctx, ecr, repo_uri: str, tag: str) -> None:
    """Log docker in with GetAuthorizationToken and push the catalog image under ``tag``.

    The registry host comes from the target's own proxyEndpoint through ``ctx.endpoint_url``, so
    an emulator's registry is reached on the emulator, never on an AWS host.
    """
    auth = ecr.get_authorization_token()["authorizationData"][0]
    user, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
    registry = urlsplit(ctx.endpoint_url(auth["proxyEndpoint"])).netloc
    target = f"{registry}/{repo_uri.split('/', 1)[1]}:{tag}"
    env = ctx.subprocess_env()

    def docker(*args: str, stdin: str | None = None) -> None:
        proc = subprocess.run(["docker", *args], input=stdin, env=env, capture_output=True,
                              text=True, timeout=_budget_s(ctx, 300))
        # The registry is the data plane: a login or push that cannot reach it at all is a missing
        # registry, not a rejected request.
        if proc.returncode != 0 and args[0] in ("login", "push") and any(
            s in proc.stderr for s in _UNREACHABLE
        ):
            raise AssertionError(
                f"DATAPLANE_UNIMPLEMENTED: docker {args[0]} could not reach the registry {registry}: "
                f"{proc.stderr[-250:]}"
            )
        assert proc.returncode == 0, f"docker {args[0]} failed rc={proc.returncode}: {proc.stderr[-250:]}"

    seeded = subprocess.run(["docker", "image", "inspect", _SOURCE_IMAGE], env=env,
                            capture_output=True, text=True, timeout=60)
    if seeded.returncode != 0:
        raise RequiredToolMissing([f"docker image {_SOURCE_IMAGE} (pre-seed it on the runner)"])
    docker("login", "--username", user, "--password-stdin", registry, stdin=password)
    docker("tag", _SOURCE_IMAGE, target)
    docker("push", target)


def _create_execution_role(ctx, name: str) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=_kv(_MANAGED_TAGS))["Role"]["Arn"]
    ctx.on_cleanup(_tolerant(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_EXEC_POLICY)
    ctx.on_cleanup(_tolerant(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_EXEC_POLICY),
                             "NoSuchEntity"))
    return arn


def _create_network(ctx) -> dict:
    """A VPC this check owns: one public subnet behind an internet gateway (Fargate pulls the
    image over a public IP) and a security group with only the default egress rule."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ctr-net-")

    def tag(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]

    net: dict = {"name": name}
    net["vpc_id"] = ec2.create_vpc(CidrBlock="10.78.0.0/16", TagSpecifications=tag("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_network(ctx, net))
    ec2.get_waiter("vpc_available").wait(VpcIds=[net["vpc_id"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    net["igw_id"] = ec2.create_internet_gateway(TagSpecifications=tag("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    net["rt_id"] = ec2.create_route_table(VpcId=net["vpc_id"], TagSpecifications=tag("route-table"))[
        "RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=net["rt_id"], DestinationCidrBlock="0.0.0.0/0", GatewayId=net["igw_id"])
    zone = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"])[0]
    net["subnet_id"] = ec2.create_subnet(VpcId=net["vpc_id"], CidrBlock="10.78.0.0/24", AvailabilityZone=zone,
                                         TagSpecifications=tag("subnet"))["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=net["subnet_id"], MapPublicIpOnLaunch={"Value": True})
    ec2.associate_route_table(RouteTableId=net["rt_id"], SubnetId=net["subnet_id"])
    net["sg_id"] = ec2.create_security_group(GroupName=name, Description="sim2real check network",
                                             VpcId=net["vpc_id"], TagSpecifications=tag("security-group"))["GroupId"]
    return net


def _delete_network(ctx, net: dict, in_body: bool = False) -> None:
    """Delete the network in dependency order, retrying while released task ENIs still hold it;
    an already-deleted piece is skipped. In the body the retries end before the run's budget."""
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + (_budget_s(ctx, _GONE_S * 2) if in_body else _GONE_S * 2)

    def retrying(fn, **kwargs):
        while True:
            try:
                fn(**kwargs)
                return
            except ClientError as exc:
                code = _err(exc)[0]
                if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                    return
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    if code == "DependencyViolation" and in_body and _budget_spent(ctx):
                        raise TimeoutError(f"{fn.__name__} clearing its dependencies: the run budget ended "
                                           "first; not graded") from exc
                    raise
            time.sleep(_POLL_S)

    if net.get("sg_id"):
        retrying(ec2.delete_security_group, GroupId=net["sg_id"])
    if net.get("subnet_id"):
        retrying(ec2.delete_subnet, SubnetId=net["subnet_id"])
    if net.get("rt_id"):
        try:
            assocs = ec2.describe_route_tables(RouteTableIds=[net["rt_id"]])["RouteTables"][0]["Associations"]
        except ClientError as exc:
            if not _err(exc)[0].endswith(".NotFound"):
                raise
            assocs = []
        for a in assocs:
            if not a.get("Main"):
                retrying(ec2.disassociate_route_table, AssociationId=a["RouteTableAssociationId"])
        retrying(ec2.delete_route_table, RouteTableId=net["rt_id"])
    if net.get("igw_id"):
        retrying(ec2.detach_internet_gateway, InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
        retrying(ec2.delete_internet_gateway, InternetGatewayId=net["igw_id"])
    retrying(ec2.delete_vpc, VpcId=net["vpc_id"])


def _force_delete_service(ecs, cluster: str, service: str) -> None:
    ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    ecs.delete_service(cluster=cluster, service=service, force=True)


# ---- ECS service: DescribeServices INACTIVE tombstone / ListServices / UpdateService -------------
def _gone_service(ctx, cluster: str, service: str, task_arn: str) -> None:
    ecs = ctx.client("ecs")
    _force_delete_service(ecs, cluster, service)
    # DRAINING is not terminal: INACTIVE is the documented tombstone.
    svc = _poll(ctx, lambda: ecs.describe_services(cluster=cluster, services=[service])["services"],
                lambda s: not s or s[0].get("status") == "INACTIVE", f"service {service} INACTIVE")
    assert svc and svc[0]["status"] == "INACTIVE", f"DescribeServices({service}) is {svc!r}, expected INACTIVE"
    arns = _paged(ecs, "list_services", "serviceArns", cluster=cluster)
    assert not [a for a in arns if a.rsplit("/", 1)[-1] == service], f"ListServices still lists {service}"
    _refused(lambda: ecs.update_service(cluster=cluster, service=service, desiredCount=1),
             ("ServiceNotActiveException",), 400, f"UpdateService on deleted {service}")
    task = _poll(ctx, lambda: ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"],
                 lambda t: not t or t[0].get("lastStatus") == "STOPPED", "the service's task STOPPED")
    assert not task or task[0]["lastStatus"] == "STOPPED", f"task still {task[0]['lastStatus']!r}"


# ---- ECS cluster: DescribeClusters INACTIVE tombstone / ListClusters / CreateService --------------
def _gone_cluster(ctx, cluster: str, td_arn: str, net: dict) -> None:
    ecs = ctx.client("ecs")
    arn = ecs.delete_cluster(cluster=cluster)["cluster"]["clusterArn"]
    got = ecs.describe_clusters(clusters=[cluster])
    states = [c.get("status") for c in got.get("clusters", [])]
    missed = [f.get("reason") for f in got.get("failures", [])]
    assert states == ["INACTIVE"] or missed == ["MISSING"], (
        f"DescribeClusters({cluster}) after delete: clusters {states!r} failures {missed!r}, "
        f"expected the INACTIVE tombstone"
    )
    assert arn not in _paged(ecs, "list_clusters", "clusterArns"), f"ListClusters still lists {cluster}"
    _refused(
        lambda: ecs.create_service(
            cluster=cluster, serviceName="gone", taskDefinition=td_arn, desiredCount=0,
            launchType="FARGATE",
            networkConfiguration={"awsvpcConfiguration": {"subnets": [net["subnet_id"]],
                                                          "securityGroups": [net["sg_id"]]}},
        ),
        ("ClusterNotFoundException",), 400, f"CreateService on deleted cluster {cluster}",
    )


# ---- ECS task definition: INACTIVE -> DELETE_IN_PROGRESS / ListTaskDefinitions(ACTIVE) ------------
def _gone_task_definition(ctx, td_arn: str, family: str) -> None:
    ecs = ctx.client("ecs")
    ecs.deregister_task_definition(taskDefinition=td_arn)
    ecs.delete_task_definitions(taskDefinitions=[td_arn])
    # The deleted revision stays describable as the documented DELETE_IN_PROGRESS tombstone.
    status = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]["status"]
    assert status in ("INACTIVE", "DELETE_IN_PROGRESS"), (
        f"task definition {td_arn.rsplit('/', 1)[-1]} is {status!r} after delete"
    )
    active = _paged(ecs, "list_task_definitions", "taskDefinitionArns", familyPrefix=family, status="ACTIVE")
    assert td_arn not in active, "ListTaskDefinitions(ACTIVE) still lists the deleted revision"


# ---- ECR repository: DescribeRepositories / list lacks / PutImageTagMutability ---------------------
def _gone_repository(ctx, repo: str) -> None:
    ecr = ctx.client("ecr")
    ecr.delete_repository(repositoryName=repo, force=True)
    nf = ("RepositoryNotFoundException",)
    _poll_refused(ctx, lambda: ecr.describe_repositories(repositoryNames=[repo]), nf, 400,
                  f"DescribeRepositories {repo}", repo)
    listed = {r["repositoryName"] for r in _paged(ecr, "describe_repositories", "repositories")}
    assert repo not in listed, f"DescribeRepositories still lists deleted repository {repo}"
    _refused(lambda: ecr.put_image_tag_mutability(repositoryName=repo, imageTagMutability="IMMUTABLE"),
             nf, 400, f"PutImageTagMutability {repo}", repo)


# ---- EC2 network: DescribeVpcs InvalidVpcID.NotFound / Name filter lacks / CreateSubnet -----------
def _gone_network(ctx, net: dict) -> None:
    ec2 = ctx.client("ec2")
    _delete_network(ctx, net, in_body=True)
    vpc = net["vpc_id"]
    nf = ("InvalidVpcID.NotFound",)
    _poll_refused(ctx, lambda: ec2.describe_vpcs(VpcIds=[vpc]), nf, 400, f"DescribeVpcs {vpc}", vpc)
    named = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [net["name"]]}])["Vpcs"]
    assert not named, f"DescribeVpcs(tag:Name) still lists {[v['VpcId'] for v in named]}"
    _refused(lambda: ec2.create_subnet(VpcId=vpc, CidrBlock="10.78.1.0/24"), nf, 400,
             f"CreateSubnet in deleted {vpc}")


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, names: str | None = None) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status``, a non-empty message naming ``names``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        if names:
            assert names in msg, f"{what}: {code} message does not name {names!r}: {msg[:200]!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(ctx, fn, codes, status, what, names=None, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, names)
                return
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what} reaching not-found: the run budget ended first; not graded")
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_log_group(ctx, name: str) -> None:
    logs = ctx.client("logs")
    logs.delete_log_group(logGroupName=name)
    nf = ("ResourceNotFoundException",)
    _poll_refused(ctx, lambda: logs.describe_log_streams(logGroupName=name), nf, 400, f"DescribeLogStreams {name}")
    listed = {g["logGroupName"] for g in logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])}
    assert name not in listed, f"DescribeLogGroups still lists deleted log group {name}"
    _refused(
        lambda: logs.put_log_events(logGroupName=name, logStreamName="gone",
                                    logEvents=[{"timestamp": int(time.time() * 1000), "message": "gone"}]),
        nf, 400, f"PutLogEvents {name}",
    )


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    _poll_refused(ctx, lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", name)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
