"""cicdchain-unhealthy-build-rollout-rejected-and-old-bytes-still-served."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cicdchain-unhealthy-build-rollout-rejected-and-old-bytes-still-served"

GROUP = "container-cicd-rollback"

SERVICES = ["codebuild", "ecr", "ecs", "elbv2", "logs"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A build whose image fails the ALB health check is rolled back by the ECS circuit breaker,
    and the ALB keeps serving the previous build's bytes; a repaired build then rolls forward.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html
    """
    est = _Estate(ctx)
    try:
        ecs = est.client("ecs")

        repo_name, repo_uri, repo_arn = _create_ecr_repo(est)
        registry = repo_uri.split("/", 1)[0]
        assert not (p := ctx.published_url_mismatch(f"https://{repo_uri}")), p

        build_log_group = _create_log_group(est, "cb-lg-")
        task_log_group = _create_log_group(est, "ecs-lg-")

        _cb_role_name, cb_role_arn = _iam_role(
            est, "codebuild", "codebuild.amazonaws.com", _codebuild_statements(repo_arn)
        )
        project = _create_codebuild_project(
            est, cb_role_arn, build_log_group, repo_uri, registry
        )

        token = est.unique_name("cicdchain-")
        build1 = _start_build(est, project, token, "good1", serve_index=True)

        vpc_id, subnet_ids = _create_public_vpc(est)
        # The ALB admits the caller on tcp/80; the tasks admit tcp/80 only from the ALB's group.
        alb_sg = _open_http_sg(est, vpc_id, 80, cidrs=ctx.ingress_cidrs())
        task_sg = _open_http_sg(est, vpc_id, 80, source_sg=alb_sg)
        tg = _create_target_group(est, vpc_id)
        tg_arn = tg["TargetGroupArn"]
        lb = _create_alb(est, subnet_ids, [alb_sg])
        _create_listener(est, lb["LoadBalancerArn"], tg_arn)

        _task_role_name, exec_role_arn = _iam_role(
            est, "ecs-exec", "ecs-tasks.amazonaws.com", _task_execution_statements(repo_arn)
        )
        cluster = _create_cluster(est)

        # The good build, deployed and serving: the content the rollback has to preserve.
        done1 = _await_build(est, build1["id"], timeout_s=1200)
        assert done1["buildStatus"] == "SUCCEEDED", _build_failure_detail(est, done1)
        digest1, size1 = _image_digest(est, repo_name, "good1")
        assert size1 > 0, f"ECR reported a zero-byte image for tag 'good1': {size1!r}"
        expected1 = f"{token} {build1['id']} good1"

        td1 = _register_task_def(
            est, f"{repo_uri}@{digest1}", task_log_group, exec_role_arn
        )
        family = td1["family"]
        svc = _create_fargate_service(
            est, cluster, td1["taskDefinitionArn"], subnet_ids, [task_sg], tg_arn
        )
        service = svc["serviceName"]

        tasks = _poll_until(
            lambda: _running_service_tasks(est, cluster, service),
            lambda ts: len(ts) == 1,
            timeout_s=600,
            interval_s=10,
            description=f"service {service} has 1 RUNNING task on the good revision",
        )
        ip1 = _task_private_ip(tasks[0])
        assert ipaddress.ip_address(ip1) in ipaddress.ip_network(_VPC_CIDR), (
            f"the task ENI address {ip1!r} the target group will register is not inside "
            f"this check's VPC CIDR {_VPC_CIDR!r}"
        )
        _poll_until(
            lambda: _target_health(est, tg_arn),
            lambda h: h.get(ip1) == "healthy",
            timeout_s=600,
            interval_s=10,
            description=f"target {ip1} healthy in {tg_arn}",
        )

        url = "http://" + lb["DNSName"] + "/"
        status1, body1 = _poll_until(
            lambda: _http_get(ctx, url),
            lambda r: r[0] == 200,
            timeout_s=600,
            interval_s=10,
            description=f"HTTP 200 through the load balancer at {url}",
        )
        assert status1 == 200, f"ALB answered {status1!r} with body {body1!r}"
        assert body1.strip() == expected1, (
            f"the ALB answered 200 but not with the good build's baked body: "
            f"expected {expected1!r}, got {body1.strip()!r}"
        )

        # Break one thing: the same build bakes its payload to a path the health check does not fetch.
        build_bad = _start_build(est, project, token, "bad", serve_index=False)
        done_bad = _await_build(est, build_bad["id"], timeout_s=1200)
        assert done_bad["buildStatus"] == "SUCCEEDED", _build_failure_detail(est, done_bad)
        digest_bad, size_bad = _image_digest(est, repo_name, "bad")
        assert size_bad > 0, f"ECR reported a zero-byte image for tag 'bad': {size_bad!r}"
        assert digest_bad != digest1, (
            f"the broken build pushed the same manifest digest {digest_bad!r} as the good one; "
            f"the two images are indistinguishable and nothing below would be observable"
        )
        expected_bad = f"{token} {build_bad['id']} bad"

        td_bad = _register_task_def(
            est, f"{repo_uri}@{digest_bad}", task_log_group, exec_role_arn, family=family
        )
        bad_arn = td_bad["taskDefinitionArn"]

        ecs.update_service(cluster=cluster, service=service, taskDefinition=bad_arn)

        # Each poll also samples the ALB and records which task IPs ever reached "healthy".
        samples: list[tuple] = []
        healthy_ips: set[str] = set()
        bad_ips: set[str] = set()
        bad_running = []

        def _observe() -> dict:
            for task in _service_tasks(est, cluster, service):
                if task.get("taskDefinitionArn") != bad_arn:
                    continue
                ip = _maybe_task_private_ip(task)
                if ip is not None:
                    bad_ips.add(ip)
                if task.get("lastStatus") == "RUNNING":
                    bad_running.append(task["taskArn"])
            for ip, state in _target_health(est, tg_arn).items():
                if state == "healthy":
                    healthy_ips.add(ip)
            samples.append(_http_get(ctx, url))
            return ecs.describe_services(cluster=cluster, services=[service])["services"][0]

        breaking = _poll_until(
            _observe,
            lambda s: _deployment_for(s, bad_arn).get("rolloutState") == "FAILED",
            timeout_s=1500,
            interval_s=10,
            description=(
                f"the deployment circuit breaker reports rolloutState FAILED for the broken "
                f"revision {bad_arn}"
            ),
        )

        # Read the verdict from the response that carried it: ECS drops the broken revision's
        # deployment from `deployments` once the rollback settles.
        failed = _deployment_for(breaking, bad_arn)
        assert failed.get("rolloutState") == "FAILED", (
            f"broken revision's deployment reported rolloutState "
            f"{failed.get('rolloutState')!r}: {failed!r}"
        )
        assert failed.get("rolloutStateReason") == _CIRCUIT_BREAKER_REASON, (
            f"ECS reported rolloutStateReason {failed.get('rolloutStateReason')!r} for the "
            f"FAILED rollout, expected {_CIRCUIT_BREAKER_REASON!r}: {failed!r}"
        )

        # ECS rolls the service back to the revision that last completed.
        rolled = _poll_until(
            _observe,
            lambda s: _primary_deployment(s).get("taskDefinition") == td1["taskDefinitionArn"]
            and _primary_deployment(s).get("rolloutState") == "COMPLETED",
            timeout_s=1200,
            interval_s=10,
            description=(
                f"service {service} rolled back to {td1['taskDefinitionArn']} with a COMPLETED "
                f"PRIMARY deployment"
            ),
        )
        assert rolled["taskDefinition"] == td1["taskDefinitionArn"], (
            f"after the rollback the service points at {rolled['taskDefinition']!r}, "
            f"expected the last good revision {td1['taskDefinitionArn']!r}"
        )

        # The bad image pulled and started, so the failure is a health-check verdict, not a crash.
        states = [
            (t.get("taskDefinitionArn"), t.get("lastStatus"), t.get("stoppedReason"))
            for t in _service_tasks(est, cluster, service)
        ]
        assert bad_running, (
            f"no task on the broken revision {bad_arn!r} was ever observed RUNNING, so the "
            f"rollback cannot be attributed to the health check; task states seen: {states!r}"
        )

        # Effect absent, three ways.
        assert len(bad_ips) >= 1, (
            f"no ENI address was ever observed for a task on {bad_arn!r}, so the health "
            f"assertion below would be vacuous"
        )
        assert not (bad_ips & healthy_ips), (
            f"the broken revision's target(s) {sorted(bad_ips & healthy_ips)!r} were reported "
            f"healthy; target group {tg_arn} saw healthy {sorted(healthy_ips)!r}"
        )
        served = [s for s in samples if s[0] == 200]
        assert len(served) >= 3, (
            f"only {len(served)} of {len(samples)} samples through {url} returned 200 during "
            f"the failed rollout, which is too few to claim the old content kept being served: "
            f"{samples!r}"
        )
        assert all(s[1].strip() == expected1 for s in served), (
            f"the ALB's body changed during the failed rollout; expected every 200 to carry "
            f"{expected1!r}, got {sorted({s[1].strip() for s in served})!r}"
        )
        assert not any(build_bad["id"] in s[1] for s in samples), (
            f"the broken build's id {build_bad['id']!r} was served through {url}: {samples!r}"
        )
        status_after, body_after = _http_get(ctx, url)
        assert status_after == 200, (
            f"after the rollback the ALB answered {status_after!r}: {body_after!r}"
        )
        assert body_after.strip() == expected1, (
            f"after the rollback the ALB serves {body_after.strip()!r}, expected the old "
            f"build's bytes {expected1!r}"
        )
        assert expected_bad != expected1, (expected1, expected_bad)

        # Positive control: repair the one broken thing and the roll-forward happens.
        build3 = _start_build(est, project, token, "good2", serve_index=True)
        done3 = _await_build(est, build3["id"], timeout_s=1200)
        assert done3["buildStatus"] == "SUCCEEDED", _build_failure_detail(est, done3)
        digest3, size3 = _image_digest(est, repo_name, "good2")
        assert size3 > 0, f"ECR reported a zero-byte image for tag 'good2': {size3!r}"
        expected3 = f"{token} {build3['id']} good2"

        td3 = _register_task_def(
            est, f"{repo_uri}@{digest3}", task_log_group, exec_role_arn, family=family
        )
        ecs.update_service(
            cluster=cluster, service=service, taskDefinition=td3["taskDefinitionArn"]
        )
        status3, body3 = _poll_until(
            lambda: _http_get(ctx, url),
            lambda r: r[0] == 200 and r[1].strip() == expected3,
            timeout_s=1200,
            interval_s=10,
            description=f"the ALB at {url} serves the repaired build's body {expected3!r}",
        )
        assert status3 == 200, f"ALB answered {status3!r} with body {body3!r}"
        assert body3.strip() == expected3, (
            f"expected the repaired build's baked body {expected3!r}, got {body3.strip()!r}"
        )
        settled = _poll_until(
            lambda: ecs.describe_services(cluster=cluster, services=[service])["services"][0],
            lambda s: _primary_deployment(s).get("taskDefinition") == td3["taskDefinitionArn"]
            and _primary_deployment(s).get("rolloutState") == "COMPLETED",
            timeout_s=1200,
            interval_s=10,
            description=f"service {service} PRIMARY deployment on the repaired revision COMPLETED",
        )
        assert _primary_deployment(settled).get("rolloutState") == "COMPLETED", (
            f"repaired rollout reported {_primary_deployment(settled)!r}"
        )
        assert settled["taskDefinition"] == td3["taskDefinitionArn"], (
            f"service points at {settled['taskDefinition']!r}, expected "
            f"{td3['taskDefinitionArn']!r}"
        )
    finally:
        # Tear down inside the check's own budget: ELB-to-ENI-to-VPC deletion takes minutes.
        est.run_now()


class _Estate:
    """A ``ctx`` that also records each teardown so ``run_now`` can run it LIFO inside the check.

    The post-check cleanup window is too short for ALB ENIs to release before VPC deletion.
    """

    def __init__(self, ctx) -> None:
        self._ctx = ctx
        self._thunks: list = []

    def __getattr__(self, name):
        return getattr(self._ctx, name)

    def on_cleanup(self, fn) -> None:
        done = []

        def once():
            if not done:
                fn()
                done.append(True)

        self._ctx.on_cleanup(once)
        self._thunks.append(once)

    def run_now(self) -> None:
        """LIFO teardown; a failure is printed so later teardowns still run, and the backstop raises it."""
        while self._thunks:
            fn = self._thunks.pop()
            try:
                fn()
            except BaseException as exc:  # noqa: BLE001 — best-effort, and reported
                print(f"teardown failed: {type(exc).__name__}: {exc}")


# The base image is pulled server-side by CodeBuild from ECR Public, so the local host needs
# no docker daemon and the build never touches a rate-limited registry.
_BASE_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"

_XSVC_PREFIX = "sim2real-xsvc-"

#: The rolloutStateReason ECS reports on the deployment its circuit breaker stopped.
_CIRCUIT_BREAKER_REASON = "ECS deployment circuit breaker: tasks failed to start."

#: Every target the ALB registers must fall inside this VPC CIDR.
_VPC_CIDR = "10.111.0.0/16"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}

#: A JSON buildspec (valid YAML) avoids quoting hazards around shell parameter expansion.
_BUILDSPEC = json.dumps(
    {
        "version": 0.2,
        "phases": {
            "pre_build": {
                "commands": [
                    'aws ecr get-login-password --region "$AWS_DEFAULT_REGION" '
                    '| docker login --username AWS --password-stdin "$REGISTRY"'
                ]
            },
            "build": {
                "commands": [
                    'echo "$DOCKERFILE_B64" | base64 -d > Dockerfile',
                    "cat Dockerfile",
                    'docker build --build-arg '
                    '"BODY=$BODY_PREFIX $CODEBUILD_BUILD_ID $IMAGE_TAG" '
                    '-t "$REPO_URI:$IMAGE_TAG" .',
                    'docker push "$REPO_URI:$IMAGE_TAG"',
                ]
            },
        },
    }
)


def _dockerfile(serve_index: bool) -> str:
    """A Dockerfile that bakes $BODY into the image at build time.

    `serve_index=False` writes it off the health-check path, so `GET /` returns 404.
    """
    target = "/www/index.html" if serve_index else "/www/not-the-health-check-path.txt"
    return (
        f"FROM {_BASE_IMAGE}\n"
        "ARG BODY\n"
        f"RUN mkdir -p /www && printf '%s\\n' \"$BODY\" > {target}\n"
        "EXPOSE 80\n"
        'CMD ["httpd","-f","-v","-p","80","-h","/www"]\n'
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn, *codes):
    """Run teardown step fn(); only an error code in `codes` (already gone) is not a failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _safe(fn):
    """Run fn() and return its result, or None if it raised (probe helper)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - probe
        return None


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_public_vpc(ctx, subnet_count: int = 2):
    """(vpc_id, [subnet_id, ...]) for a VPC with an internet gateway, created and destroyed here.

    An IGW plus assignPublicIp lets Fargate pull from ECR and the ALB be reachable, with no NAT.
    """
    ec2 = ctx.client("ec2")
    azs = _usable_azs(ctx, subnet_count)

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            try:
                _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
                return
            except Exception:  # noqa: BLE001 - a dependency is still detaching
                time.sleep(2)
        raise RuntimeError(f"vpc {vpc_id} could not be deleted")

    ctx.on_cleanup(_drop_vpc)

    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_kv()}]
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _unless_gone(
            lambda: _delete_net(ec2, "detach_internet_gateway", 
                InternetGatewayId=igw_id, VpcId=vpc_id
            ),
            "Gateway.NotAttached",
        )
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            try:
                _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
                return
            except Exception:  # noqa: BLE001 - still attached
                time.sleep(2)
        raise RuntimeError(f"internet gateway {igw_id} could not be deleted")

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_kv()}],
    )["RouteTable"]["RouteTableId"]

    def _drop_rtb():
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            try:
                _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)
                return
            except Exception:  # noqa: BLE001 - association still present
                time.sleep(2)
        raise RuntimeError(f"route table {rtb_id} could not be deleted")

    ctx.on_cleanup(_drop_rtb)
    ec2.create_route(
        RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )

    subnet_ids: list[str] = []
    for index, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=str(list(ipaddress.ip_network(_VPC_CIDR).subnets(new_prefix=24))[index]),
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]

        def _drop_subnet(sid=subnet_id):
            deadline = time.monotonic() + 300.0
            while time.monotonic() < deadline:
                try:
                    _delete_net(ec2, "delete_subnet", SubnetId=sid)
                    return
                except Exception:  # noqa: BLE001 - an ENI is still detaching
                    time.sleep(2)
            raise RuntimeError(f"subnet {sid} could not be deleted")

        ctx.on_cleanup(_drop_subnet)
        ec2.modify_subnet_attribute(
            SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True}
        )
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)[
            "AssociationId"
        ]
        ctx.on_cleanup(
            lambda a=assoc: _unless_gone(
                lambda: ec2.disassociate_route_table(AssociationId=a),
                "InvalidAssociationID.NotFound",
            )
        )
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _usable_azs(ctx, want: int) -> list[str]:
    """`want` AZ names in this region; AZ names are per-account aliases, so never hardcoded.

    Local and Wavelength zones are excluded: they cannot host an ALB subnet.
    """
    zones = [
        z["ZoneName"]
        for z in ctx.client("ec2").describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    ]
    zones.sort()
    assert len(zones) >= want, (
        f"{ctx.region} offers {len(zones)} available availability zones {zones!r}, "
        f"need {want} for an internet-facing ALB"
    )
    return zones[:want]


def _open_http_sg(ctx, vpc_id: str, port: int = 80, *, cidrs=(), source_sg=None) -> str:
    """A security group allowing inbound tcp/port from cidrs or source_sg, tagged at creation.

    The delete is retried because ENIs keep the group referenced after their owner is deleted.
    """
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name(_XSVC_PREFIX + "sg-"),
        Description="sim2real xsvc cicd chain HTTP ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _drop():
        deadline = time.monotonic() + 240.0
        while time.monotonic() < deadline:
            try:
                _delete_net(ec2, "delete_security_group", GroupId=gid)
                return
            except Exception:  # noqa: BLE001 - ENI still detaching
                time.sleep(2)
        raise RuntimeError(f"security group {gid} could not be deleted")

    ctx.on_cleanup(_drop)
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": c} for c in cidrs],
                "UserIdGroupPairs": [{"GroupId": source_sg}] if source_sg else [],
            }
        ],
    )
    return gid


def _iam_role(ctx, kind, trust_service, statements):
    """Create a role trusting trust_service with one inline policy; return (name, arn).

    The role is polled back (IAM is eventually consistent); trust propagation is retried by callers.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name(_XSVC_PREFIX + kind + "-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trust_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _drop():
        _unless_gone(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity")
        _unless_gone(lambda: iam.delete_role(RoleName=name), "NoSuchEntity")

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    _poll_until(
        lambda: _safe(lambda: iam.get_role_policy(RoleName=name, PolicyName="inline")),
        lambda r: r is not None,
        timeout_s=60,
        interval_s=2,
        description=f"role {name} inline policy readable",
    )
    return name, arn


def _codebuild_statements(repo_arn: str) -> list[dict]:
    """The permissions a docker build+push needs, with writes scoped to this check's repository."""
    return [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "*",
        },
        {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeImages",
                "ecr:GetDownloadUrlForLayer",
                "ecr:InitiateLayerUpload",
                "ecr:PutImage",
                "ecr:UploadLayerPart",
            ],
            "Resource": repo_arn,
        },
    ]


def _task_execution_statements(repo_arn: str) -> list[dict]:
    """The Fargate agent's pull+log permissions, scoped to this check's repository."""
    return [
        {"Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer",
            ],
            "Resource": repo_arn,
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
    ]


def _create_ecr_repo(ctx):
    """(name, repositoryUri, arn) for a private repository deleted with force=True."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name(_XSVC_PREFIX + "ecr-")
    repo = ecr.create_repository(
        repositoryName=name,
        imageScanningConfiguration={"scanOnPush": False},
        imageTagMutability="MUTABLE",
        tags=_tags_kv(),
    )["repository"]
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: ecr.delete_repository(repositoryName=name, force=True),
            "RepositoryNotFoundException",
        )
    )
    return name, repo["repositoryUri"], repo["repositoryArn"]


def _create_log_group(ctx, kind: str) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(_XSVC_PREFIX + kind)
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))

    def _drop():
        # A buffered stream can flush after the delete and recreate the group, so loop.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            _unless_gone(lambda: logs.delete_log_group(logGroupName=name), "ResourceNotFoundException")
            time.sleep(2)
            if not logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups"):
                return
        raise RuntimeError(f"log group {name} kept reappearing after delete")

    ctx.on_cleanup(_drop)
    return name


def _create_codebuild_project(ctx, role_arn, log_group, repo_uri, registry) -> str:
    """A privileged LINUX_CONTAINER project (docker daemon available) that can run `docker build`.

    Logging goes to a log group this check owns, so no `/aws/codebuild/<project>` group remains.
    """
    cb = ctx.client("codebuild")
    name = ctx.unique_name(_XSVC_PREFIX + "cb-")
    kwargs = dict(
        name=name,
        source={"type": "NO_SOURCE", "buildspec": _BUILDSPEC},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
            "privilegedMode": True,
            "environmentVariables": [
                {"name": "REPO_URI", "value": repo_uri},
                {"name": "REGISTRY", "value": registry},
            ],
        },
        serviceRole=role_arn,
        timeoutInMinutes=20,
        logsConfig={"cloudWatchLogs": {"status": "ENABLED", "groupName": log_group}},
        tags=[{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()],
    )
    project = _settle_role(
        lambda: cb.create_project(**kwargs),
        ("InvalidInputException",),
        description="CreateProject with a freshly created service role",
    )["project"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: cb.delete_project(name=name), "ResourceNotFoundException"))
    assert project["serviceRole"] == role_arn, (
        f"project serviceRole {project['serviceRole']!r} != {role_arn!r}"
    )
    return name


def _settle_role(call, codes, *, budget_s=120.0, interval_s=2.0, description="call"):
    """Retry `call` while it fails with one of `codes`, bounded; re-raise the last error.

    Trust-policy propagation to a service principal has no signal other than this error.
    """
    last = None
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            last = exc
            if exc.response["Error"]["Code"] in codes:
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"{description} never settled: {last!r}")


def _start_build(ctx, project: str, token: str, tag: str, *, serve_index: bool):
    """StartBuild with this build's identity passed as environment overrides.

    The served body includes CODEBUILD_BUILD_ID, so it can only have come from this build.
    """
    cb = ctx.client("codebuild")
    # Retried on account-level codes (project not yet readable, account build queue full,
    # throttling), which say nothing about the claim under test.
    build = _settle_role(
        lambda: cb.start_build(
            projectName=project,
            environmentVariablesOverride=[
                {"name": "BODY_PREFIX", "value": token},
                {"name": "IMAGE_TAG", "value": tag},
                {
                    "name": "DOCKERFILE_B64",
                    "value": base64.b64encode(
                        _dockerfile(serve_index).encode("utf-8")
                    ).decode("ascii"),
                },
            ],
        ),
        ("InvalidInputException", "AccountLimitExceededException", "ThrottlingException"),
        description=f"StartBuild for tag {tag!r}",
    )["build"]
    bid = build["id"]
    ctx.on_cleanup(lambda: cb.batch_delete_builds(ids=[bid]))
    assert build["projectName"] == project, (
        f"StartBuild returned a build of project {build['projectName']!r}, expected {project!r}"
    )
    assert build["buildStatus"] == "IN_PROGRESS", (
        f"StartBuild returned buildStatus {build['buildStatus']!r}"
    )
    return build


def _await_build(ctx, build_id: str, timeout_s: float = 1200.0) -> dict:
    """Poll BatchGetBuilds until the build leaves IN_PROGRESS; return the final build."""
    cb = ctx.client("codebuild")
    return _poll_until(
        lambda: cb.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b.get("buildStatus") != "IN_PROGRESS",
        timeout_s=timeout_s,
        interval_s=10,
        description=f"build {build_id} leaves IN_PROGRESS",
    )


def _build_failure_detail(ctx, build: dict) -> str:
    """A readable failure: which phase failed, its context, and the tail of the build log."""
    parts = [f"build {build.get('id')!r} ended {build.get('buildStatus')!r}"]
    for phase in build.get("phases", []):
        if phase.get("phaseStatus") in (None, "SUCCEEDED"):
            continue
        contexts = "; ".join(
            c.get("message", "") for c in phase.get("contexts", []) if c.get("message")
        )
        parts.append(
            f"phase {phase.get('phaseType')!r}={phase.get('phaseStatus')!r} {contexts}"
        )
    logs = build.get("logs") or {}
    group, stream = logs.get("groupName"), logs.get("streamName")
    if group and stream:
        events = _safe(
            lambda: ctx.client("logs").get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=False, limit=40
            )
        )
        tail = [e.get("message", "").rstrip() for e in (events or {}).get("events", [])]
        parts.append("log tail: " + " | ".join(tail[-25:]))
    return "\n".join(parts)


def _image_digest(ctx, repo_name: str, tag: str):
    """(imageDigest, imageSizeInBytes) for `tag` — the bytes the build actually pushed."""
    details = ctx.client("ecr").describe_images(
        repositoryName=repo_name, imageIds=[{"imageTag": tag}]
    )["imageDetails"]
    assert len(details) == 1, f"expected one image for tag {tag!r}, got {details!r}"
    detail = details[0]
    assert tag in detail.get("imageTags", []), (
        f"ECR image {detail.get('imageDigest')!r} does not carry tag {tag!r}: "
        f"{detail.get('imageTags')!r}"
    )
    return detail["imageDigest"], detail["imageSizeInBytes"]


def _ensure_ecs_slr(ctx) -> None:
    """Fargate needs AWSServiceRoleForECS. Idempotent — already-exists is success."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInput":
            raise


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags_kv())

    def _drop():
        deadline = time.monotonic() + 100.0
        while time.monotonic() < deadline:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except Exception:  # noqa: BLE001 - a draining service still blocks it
                time.sleep(2)
        raise RuntimeError(f"ecs cluster {name} could not be deleted")

    ctx.on_cleanup(_drop)
    return name


def _awslogs(log_group: str, region: str, prefix: str = "ecs") -> dict:
    return {
        "logDriver": "awslogs",
        "options": {
            "awslogs-group": log_group,
            "awslogs-region": region,
            "awslogs-stream-prefix": prefix,
        },
    }


def _register_task_def(ctx, image: str, log_group: str, exec_role_arn: str, family=None):
    """A Fargate task definition whose container is pinned by `repositoryUri@sha256:...`."""
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=family or ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": image,
                "essential": True,
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
                "logConfiguration": _awslogs(log_group, ctx.region, "ecs"),
            }
        ],
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        tags=_ecs_tags_kv(),
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    def _drop():
        # A deregistered revision stays listed as INACTIVE until it is deleted as well.
        ecs.deregister_task_definition(taskDefinition=arn)
        failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
        if failures:
            raise RuntimeError(f"DeleteTaskDefinitions failed for {arn}: {failures!r}")

    ctx.on_cleanup(_drop)
    return td


def _create_fargate_service(
    ctx, cluster, td_arn, subnets, sg_ids, tg_arn, *, desired_count=1
):
    """A Fargate service behind `tg_arn`, with the deployment circuit breaker armed.

    Teardown drains it first, because an ACTIVE service blocks cluster deletion.
    """
    _ensure_ecs_slr(ctx)
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "ecs-svc-")
    kwargs = dict(
        cluster=cluster,
        serviceName=name,
        taskDefinition=td_arn,
        desiredCount=desired_count,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets,
                "securityGroups": sg_ids,
                "assignPublicIp": "ENABLED",
            }
        },
        loadBalancers=[
            {"targetGroupArn": tg_arn, "containerName": "app", "containerPort": 80}
        ],
        healthCheckGracePeriodSeconds=30,
        deploymentConfiguration={
            "deploymentCircuitBreaker": {"enable": True, "rollback": True},
            "maximumPercent": 200,
            "minimumHealthyPercent": 100,
        },
        tags=_ecs_tags_kv(),
    )
    svc = _settle_role(
        lambda: ecs.create_service(**kwargs)["service"],
        ("InvalidParameterException", "ClientException"),
        description="CreateService with a freshly created execution role",
    )

    def _drop():
        _unless_gone(
            lambda: ecs.update_service(cluster=cluster, service=name, desiredCount=0),
            "ServiceNotFoundException",
            "ServiceNotActiveException",
        )
        _unless_gone(
            lambda: ecs.delete_service(cluster=cluster, service=name, force=True),
            "ServiceNotFoundException",
        )
        _poll_until(
            lambda: (
                ecs.describe_services(cluster=cluster, services=[name]).get(
                    "services"
                )
                or [{}]
            )[0].get("status", "INACTIVE"),
            lambda st: st == "INACTIVE",
            timeout_s=300,
            interval_s=2,
            description=f"service {name} drained to INACTIVE",
        )

    ctx.on_cleanup(_drop)
    return svc


def _primary_deployment(service: dict) -> dict:
    """The service's PRIMARY deployment, or {} if ECS reports none."""
    for dep in service.get("deployments", []):
        if dep.get("status") == "PRIMARY":
            return dep
    return {}


def _service_task_arns(ctx, cluster, service) -> list[str]:
    """Every RUNNING-desired task ARN of the service, paginated."""
    ecs = ctx.client("ecs")
    arns: list[str] = []
    token = None
    while True:
        kwargs = dict(cluster=cluster, serviceName=service, desiredStatus="RUNNING")
        if token:
            kwargs["nextToken"] = token
        page = ecs.list_tasks(**kwargs)
        arns.extend(page.get("taskArns", []))
        token = page.get("nextToken")
        if not token:
            return arns


def _running_service_tasks(ctx, cluster, service) -> list[dict]:
    """DescribeTasks for the service's RUNNING-desired tasks; raises if one already STOPPED,
    so an image-pull or startup failure surfaces as itself instead of as a poll timeout."""
    ecs = ctx.client("ecs")
    arns = _service_task_arns(ctx, cluster, service)
    if not arns:
        return []
    tasks = ecs.describe_tasks(cluster=cluster, tasks=arns).get("tasks", [])
    for task in tasks:
        if task.get("lastStatus") == "STOPPED":
            raise AssertionError(
                f"service task stopped: stopCode={task.get('stopCode')!r} "
                f"reason={task.get('stoppedReason')!r}"
            )
    return [t for t in tasks if t.get("lastStatus") == "RUNNING"]


def _create_target_group(ctx, vpc_id):
    """An ip-target group health-checking `GET /` for a 200, with a 5 s deregistration delay
    so a roll-forward's deregistration is observable within the run."""
    elb = ctx.client("elbv2")
    tg = elb.create_target_group(
        Name=ctx.unique_name(_XSVC_PREFIX + "tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=10,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        HealthCheckTimeoutSeconds=5,
        Matcher={"HttpCode": "200"},
        Tags=_tags_kv(),
    )["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop():
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except Exception:  # noqa: BLE001 - still referenced by a listener/service
                time.sleep(2)
        raise RuntimeError(f"target group {arn} could not be deleted")

    ctx.on_cleanup(_drop)
    elb.modify_target_group_attributes(
        TargetGroupArn=arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "5"}],
    )
    return tg


def _create_alb(ctx, subnets, sg_ids):
    """An internet-facing ALB, waited to 'active', so the check can GET through it from outside."""
    elb = ctx.client("elbv2")
    lb = elb.create_load_balancer(
        Name=ctx.unique_name(_XSVC_PREFIX + "lb-"),
        Subnets=subnets,
        SecurityGroups=sg_ids,
        Scheme="internet-facing",
        Type="application",
        IpAddressType="ipv4",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop():
        _unless_gone(lambda: elb.delete_load_balancer(LoadBalancerArn=arn), "LoadBalancerNotFound")
        # Wait for the ALB's ENIs to go away before the security group teardown runs.
        deadline = time.monotonic() + 180.0
        while time.monotonic() < deadline:
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)
        raise RuntimeError(f"load balancer {arn} still present after delete")

    ctx.on_cleanup(_drop)
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "failed"),
        timeout_s=600,
        interval_s=10,
        description=f"load balancer {arn} active",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}"
    return lb


def _create_listener(ctx, lb_arn, tg_arn, port=80):
    elb = ctx.client("elbv2")
    listener = elb.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(),
    )["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: elb.delete_listener(ListenerArn=arn), "ListenerNotFound"))
    return listener


def _target_health(ctx, tg_arn) -> dict[str, str]:
    """{target-id: health-state} for every target currently in the group."""
    descs = ctx.client("elbv2").describe_target_health(TargetGroupArn=tg_arn)[
        "TargetHealthDescriptions"
    ]
    return {d["Target"]["Id"]: d["TargetHealth"]["State"] for d in descs}


def _maybe_task_private_ip(task: dict) -> str | None:
    """The awsvpc ENI's private IPv4 if attached yet, else None (PROVISIONING/STOPPED tasks)."""
    for att in task.get("attachments", []):
        if att.get("type") == "ElasticNetworkInterface":
            for detail in att.get("details", []):
                if detail.get("name") == "privateIPv4Address":
                    return detail["value"]
    return None


def _task_private_ip(task: dict) -> str:
    """The awsvpc ENI's private IPv4 (what an 'ip' target group registers); raises if absent."""
    ip = _maybe_task_private_ip(task)
    if ip is None:
        raise AssertionError(
            f"task {task.get('taskArn')!r} exposes no awsvpc privateIPv4Address; "
            f"attachments were {task.get('attachments')!r}"
        )
    return ip


def _http_get(ctx, url: str, timeout_s: float = 10.0):
    """(status, body) for a plain GET; an HTTP error status is returned, not raised.

    A transport failure (DNS not yet propagated, connection refused) returns (None, reason).
    """
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**({"User-Agent": "sim2real-xsvc"}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # transport-level, retried by the caller
        return None, f"{type(exc).__name__}: {exc}"


def _service_tasks(ctx, cluster, service) -> list[dict]:
    """Every task of the service, RUNNING- and STOPPED-desired, paginated; never raises on a stop.

    Stopped tasks are the evidence that the circuit breaker acted.
    """
    ecs = ctx.client("ecs")
    arns: list[str] = []
    for desired in ("RUNNING", "STOPPED"):
        token = None
        while True:
            kwargs = dict(cluster=cluster, serviceName=service, desiredStatus=desired)
            if token:
                kwargs["nextToken"] = token
            page = ecs.list_tasks(**kwargs)
            arns.extend(page.get("taskArns", []))
            token = page.get("nextToken")
            if not token:
                break
    out: list[dict] = []
    for i in range(0, len(arns), 100):
        out.extend(
            ecs.describe_tasks(cluster=cluster, tasks=arns[i : i + 100]).get("tasks", [])
        )
    return out


def _deployment_for(service: dict, task_def_arn: str) -> dict:
    """The service's deployment for `task_def_arn`, whatever its status, or {}."""
    for dep in service.get("deployments", []):
        if dep.get("taskDefinition") == task_def_arn:
            return dep
    return {}


# Load balancers and similar resources delete asynchronously, leaving ENIs in the subnet or
# security group; network deletes wait (bounded) for them and retry DependencyViolation.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return None
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
