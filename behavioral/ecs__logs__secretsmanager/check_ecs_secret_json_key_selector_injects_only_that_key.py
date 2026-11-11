"""ecs-secret-json-key-selector-injects-only-that-key."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-secret-json-key-selector-injects-only-that-key"
GROUP = "container-secret-injection"
SERVICES = ["ecs", "logs", "secretsmanager"]

_KEY = "PASSWORD"
_OTHER_KEY = "USERNAME"
_MISSING_KEY = "NO_SUCH_KEY_IN_THIS_SECRET"
_STREAM_PREFIX = "sim2real"

_OK = 0
_SELECTOR_IGNORED = 3
_JUST_KEY_EMPTY = 4
_WHOLE_NOT_JSON = 5
_MISMATCH = 8

_TASK_TIMEOUT_S = 600.0
_LOG_TIMEOUT_S = 300.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A `secrets` valueFrom with a json-key suffix injects ONLY that key's value while the bare ARN
    injects the whole JSON document; a json-key the secret lacks stops the task at start.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html
    """
    ecs = ctx.client("ecs")
    secret_arn, password = _secret(ctx)
    log_group = _log_group(ctx)
    exec_role_arn = _execution_role(ctx, secret_arn, log_group)
    cluster = _create_cluster(ctx, ecs)
    subnet_id, sg_id = _public_network(ctx)

    good_td = _register(ctx, ecs, exec_role_arn, log_group, secret_arn, _KEY)
    bad_td = _register(ctx, ecs, exec_role_arn, log_group, secret_arn, _MISSING_KEY)

    # Suffix form is <arn>:<json-key>:<version-stage>:<version-id>, the last two left empty.
    described = ecs.describe_task_definition(taskDefinition=good_td)["taskDefinition"]
    refs = {
        s["name"]: s["valueFrom"] for s in described["containerDefinitions"][0]["secrets"]
    }
    assert refs == {"WHOLE": secret_arn, "JUST_KEY": f"{secret_arn}:{_KEY}::"}, (
        f"both secret references must round-trip byte-for-byte and remain distinct, got {refs!r}"
    )

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    good_arn = _run(ctx, ecs, cluster, good_td, net)
    bad_arn = _run(ctx, ecs, cluster, bad_td, net)

    good = _await_stopped(ecs, cluster, good_arn, "positive (json-key PASSWORD)")
    bad = _await_stopped(ecs, cluster, bad_arn, "negative (json-key absent from the secret)",
                         allow_failed_start=True)

    container = _container(good, "app")
    code = container.get("exitCode")
    meaning = {
        _SELECTOR_IGNORED: (
            "JUST_KEY received the WHOLE JSON document — the json-key suffix was ignored"
        ),
        _JUST_KEY_EMPTY: "JUST_KEY was empty or unset — nothing was injected for the selector",
        _WHOLE_NOT_JSON: (
            "WHOLE was not the whole JSON document — the suffix was applied to the bare reference too"
        ),
        _MISMATCH: (
            'JUST_KEY was not the value of the "PASSWORD" key inside WHOLE — the wrong key was '
            "selected"
        ),
    }
    assert code == _OK, (
        f"the json-key reference must inject exactly the PASSWORD value and the bare reference the "
        f"whole document: {meaning.get(code, 'unexpected exit code')} (exitCode={code!r}, "
        f"reason={container.get('reason')!r}, stoppedReason={good.get('stoppedReason')!r})"
    )

    # Second, independent observable at a different destination (CloudWatch Logs): the marker line
    # reports the two lengths, which must differ in the direction only a real selection produces.
    marker = _marker_line(ctx, log_group, good_arn)
    lengths = dict(
        part.split("=", 1) for part in marker.split() if "=" in part
    )
    just_len = int(lengths["just_key_len"])
    whole_len = int(lengths["whole_len"])
    assert just_len == len(password), (
        f"the container reported a JUST_KEY of {just_len} characters, but the PASSWORD value in the "
        f"secret is {len(password)} characters long"
    )
    assert whole_len > just_len, (
        f"the whole JSON document must be longer than the single value selected out of it: "
        f"whole={whole_len} vs just_key={just_len} (marker line {marker!r})"
    )

    assert bad.get("stopCode") == "TaskFailedToStart", (
        f"a secrets entry naming a json-key the secret does not contain must stop the task before it "
        f"runs, rather than injecting an empty value: got stopCode={bad.get('stopCode')!r} "
        f"stoppedReason={bad.get('stoppedReason')!r}"
    )
    assert _container(bad, "app").get("exitCode") is None, (
        f"the negative task's container must never have run, so it must have no exitCode; got "
        f"{_container(bad, 'app').get('exitCode')!r}"
    )
    reason = bad.get("stoppedReason") or ""
    assert _MISSING_KEY in reason or "secret" in reason.lower(), (
        f"the failure must name the secret or the missing key so an operator can act on it; "
        f"stoppedReason={reason!r}"
    )


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

# The container proves the relationship itself: it never learns the expected secret value, it checks
# that JUST_KEY is exactly what WHOLE says the PASSWORD key holds. Only lengths are ever printed.
_PROBE = (
    f'[ -n "$JUST_KEY" ] || exit {_JUST_KEY_EMPTY}; '
    f"case \"$WHOLE\" in '{{'*) ;; *) exit {_WHOLE_NOT_JSON};; esac; "
    f'[ "$JUST_KEY" = "$WHOLE" ] && exit {_SELECTOR_IGNORED}; '
    f'case "$WHOLE" in *"\\"{_KEY}\\":\\"$JUST_KEY\\""*) ;; *) exit {_MISMATCH};; esac; '
    f'echo "{_STREAM_PREFIX}-marker just_key_len=${{#JUST_KEY}} whole_len=${{#WHOLE}}"; '
    f"exit {_OK}"
)


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run fn(), swallowing any exception. Teardown ONLY — never on an assertion path."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound", "NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observed {last!r}"
    )


def _container(task, name) -> dict:
    for c in task["containers"]:
        if c["name"] == name:
            return c
    raise AssertionError(
        f"task {task['taskArn']} has no container named {name!r}; got "
        f"{[c['name'] for c in task['containers']]!r}"
    )


def _secret(ctx):
    """A secret whose SecretString is a compact two-key JSON document. Returns (arn, password).

    Compact separators make `"PASSWORD":"<value>"` a literal substring the container can check.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-ecs-jsonkey-")
    password = ctx.unique_name("pw-")
    document = json.dumps(
        {_OTHER_KEY: "sim2real-user", _KEY: password}, separators=(",", ":")
    )
    arn = sm.create_secret(
        Name=name,
        SecretString=document,
        Tags=_ec2_tags(),
    )["ARN"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
        )
    )
    stored = sm.get_secret_value(SecretId=arn)["SecretString"]
    assert stored == document, (
        f"the secret must be stored byte-for-byte for the in-container substring proof to hold: "
        f"stored {len(stored)} chars, wrote {len(document)}"
    )
    return arn, password


def _log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("/sim2real/behav/ecs-jsonkey-")
    logs.create_log_group(logGroupName=name, tags=dict(_MANAGED_TAGS))
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=name)))
    return name


def _execution_role(ctx, secret_arn, log_group) -> str:
    """An execution role that may read exactly this secret and write exactly this log group."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-ecs-execrole-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_ec2_tags()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=name)))
    managed = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=managed)
    ctx.on_cleanup(
        lambda: _swallow(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=managed))
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": secret_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    )
    assert log_group, "the log group must exist before the execution role is granted access to it"
    return arn


def _register(ctx, ecs, exec_role_arn, log_group, secret_arn, json_key) -> str:
    arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-jsonkey-td-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", _PROBE],
                "secrets": [
                    {"name": "WHOLE", "valueFrom": secret_arn},
                    {"name": "JUST_KEY", "valueFrom": f"{secret_arn}:{json_key}::"},
                ],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": _STREAM_PREFIX,
                    },
                },
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        tags=_ecs_tags(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn)))
    return arn


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=name)))
    return name


def _run(ctx, ecs, cluster, td_arn, net) -> str:
    """RunTask, retrying only while the freshly created execution role is still propagating."""

    def _attempt():
        try:
            return ecs.run_task(
                cluster=cluster,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net,
                tags=_ecs_tags(),
            )
        except ClientError as exc:
            return exc

    resp = _poll_until(
        _attempt,
        lambda r: not isinstance(r, ClientError),
        timeout_s=180,
        interval_s=10,
        description="the freshly created execution role propagates enough for ECS to assume it",
    )
    assert not resp.get("failures"), f"RunTask reported failures: {resp.get('failures')!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
    )
    return arn


def _await_stopped(ecs, cluster, arn, label, *, allow_failed_start=False) -> dict:
    task = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=_TASK_TIMEOUT_S,
        interval_s=10,
        description=f"the {label} task reaches STOPPED",
    )
    if not allow_failed_start:
        assert task.get("stopCode") != "TaskFailedToStart", (
            f"the {label} task never started, so nothing about secret injection was measured: "
            f"stoppedReason={task.get('stoppedReason')!r} containers={task.get('containers')!r}"
        )
    return task


def _marker_line(ctx, log_group, task_arn) -> str:
    """The one marker line the probe wrote, read back from CloudWatch Logs.

    Polled: Logs ingestion trails the container's exit; a stream without the line raises.
    """
    logs = ctx.client("logs")
    stream = f"{_STREAM_PREFIX}/app/{task_arn.rsplit('/', 1)[-1]}"

    def _lines():
        try:
            events = logs.get_log_events(
                logGroupName=log_group, logStreamName=stream, startFromHead=True
            )["events"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return []
            raise
        return [e["message"] for e in events]

    found = _poll_until(
        _lines,
        lambda ls: any(f"{_STREAM_PREFIX}-marker" in line for line in ls),
        timeout_s=_LOG_TIMEOUT_S,
        interval_s=10,
        description=f"the probe's marker line reaches {log_group}/{stream}",
    )
    return next(line for line in found if f"{_STREAM_PREFIX}-marker" in line)


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    Not the default VPC, which an account may lack or have broken DHCP options on. The public
    route lets the task pull busybox from public ECR and the agent reach Secrets Manager.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.190.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.190.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags()}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _ec2_tags()}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
            "SecurityGroups"
        ]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if not ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
            ).get("NetworkInterfaces", []):
                break
            time.sleep(10)
        while time.monotonic() < deadline:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                    break
                time.sleep(10)
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(10)
        raise RuntimeError(
            f"vpc {vpc_id} / subnet {subnet_id} not deleted within the teardown deadline"
        )

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
