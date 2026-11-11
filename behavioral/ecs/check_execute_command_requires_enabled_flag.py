"""execute-command-requires-enabled-flag."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-command-requires-enabled-flag"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteCommand on a RUNNING task launched without enableExecuteCommand is rejected with a
    not-enabled error, not TargetNotConnectedException; the same task definition on the same
    container instance launched WITH the flag gets a different outcome, isolating the flag."""
    ecs = ctx.client("ecs")

    cluster_arn = _create_cluster(ctx)
    # Real AWS cryptographically validates the instance identity document/signature pair
    # on RegisterContainerInstance and rejects an omitted (or synthetic) pair with
    # InvalidParameterException ("...were not valid"). Provision a real, running EC2
    # instance and pull ITS genuine, AWS-signed identity document/signature via SSM Run
    # Command so the registration is actually accepted.
    doc, sig = _launch_identity_source_instance(ctx)
    _register_container_instance(ctx, cluster_arn, doc, sig)
    task_role_arn = _create_task_role(ctx)
    task_def_arn = _register_minimal_task_def(ctx, ecs, task_role_arn)


    run_resp = _run_task_tolerating_role_propagation(
        ecs, cluster=cluster_arn, task_def_arn=task_def_arn, enable_execute_command=False
    )
    assert not run_resp.get("failures"), f"RunTask failures: {run_resp.get('failures')}"
    task = run_resp["tasks"][0]
    task_arn = task["taskArn"]
    assert task.get("enableExecuteCommand") is False, (
        f"expected the task to report enableExecuteCommand=False since RunTask was not "
        f"passed the flag, got {task.get('enableExecuteCommand')!r}"
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.submit_task_state_change(cluster=cluster_arn, task=task_arn, status="STOPPED"))
    )
    # A PENDING task gets the SAME InvalidParameterException as the not-enabled case, and with no
    # live agent nothing advances it, so report RUNNING on the agent's behalf.
    _advance_to_running(ecs, cluster_arn, task_arn)

    error = _refusal(
        lambda: ecs.execute_command(
            cluster=cluster_arn,
            task=task_arn,
            container="app",
            command="/bin/sh",
            interactive=True,
        )
    )
    code = error["Code"]
    assert code != "AccessDeniedException", (
        "got AccessDeniedException -- this masks the real boundary being tested "
        "(execute-command-not-enabled), check IAM permissions for the test principal"
    )
    assert code == "InvalidParameterException", (
        f"expected the execute-command-not-enabled rejection InvalidParameterException, got {code!r}"
    )
    message = error["Message"]
    assert message == (
        "The execute command failed because execute command was not enabled when the task was run or the "
        "execute command agent isn't running. Wait and try again or run a new task with execute command "
        "enabled and try again."
    ), f"expected the execute-command-not-enabled message, got {message!r}"
    # It must specifically NOT be the connectivity error, which is what real ECS returns
    # once the flag *is* enabled but the (real) SSM-managed agent isn't connected -- i.e.
    # the flag check happens strictly before any target-connectivity check.
    assert code != "TargetNotConnectedException", (
        f"got TargetNotConnectedException -- this is the connectivity error real ECS "
        f"raises once the flag IS enabled, so seeing it here means the flag check did "
        f"not run before the connectivity check, got {code!r}"
    )

    # Positive control: the cluster, container instance and task def are identical; only the flag
    # differs, so a differing outcome isolates the flag as the enforced boundary.
    run_resp2 = _run_task_tolerating_role_propagation(
        ecs, cluster=cluster_arn, task_def_arn=task_def_arn, enable_execute_command=True
    )
    assert not run_resp2.get("failures"), f"RunTask (flag=True) failures: {run_resp2.get('failures')}"
    task2 = run_resp2["tasks"][0]
    task2_arn = task2["taskArn"]
    assert task2.get("enableExecuteCommand") is True, (
        f"expected the task to report enableExecuteCommand=True since RunTask was "
        f"passed the flag, got {task2.get('enableExecuteCommand')!r}"
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.submit_task_state_change(cluster=cluster_arn, task=task2_arn, status="STOPPED"))
    )
    _advance_to_running(ecs, cluster_arn, task2_arn, connect_exec_agent=True)

    code2 = _outcome(
        lambda: ecs.execute_command(
            cluster=cluster_arn,
            task=task2_arn,
            container="app",
            command="/bin/sh",
            interactive=True,
        )
    )
    assert code2 != code, (
        f"enabling enableExecuteCommand must change ExecuteCommand's outcome -- got the "
        f"SAME {code!r} with the flag True as with it False, so the earlier rejection "
        f"cannot be attributed to the flag rather than to some other property of this "
        f"container instance"
    )




def _advance_to_running(ecs, cluster_arn: str, task_arn: str, *, connect_exec_agent: bool = False) -> None:
    kwargs = {}
    if connect_exec_agent:
        # A real ECS-exec-enabled agent reports its own managed-agent status via the
        # SAME agent-facing API used for lastStatus. TargetNotConnectedException is
        # reserved for a task whose ExecuteCommandAgent previously reached RUNNING and
        # then lost connectivity -- reproducing that requires impersonating this
        # report too, the same way registration and lastStatus already are.
        kwargs["managedAgents"] = [
            {
                "containerName": "app",
                "managedAgentName": "ExecuteCommandAgent",
                "status": "RUNNING",
                "reason": "sim2real-behav: simulated exec agent connected",
            }
        ]
    ecs.submit_task_state_change(
        cluster=cluster_arn,
        task=task_arn,
        status="RUNNING",
        reason="sim2real-behav: simulated agent-reported running",
        **kwargs,
    )

    def _probe():
        t = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
        if not connect_exec_agent:
            return t["lastStatus"]
        container = next((c for c in t.get("containers", []) if c["name"] == "app"), None)
        agents = container.get("managedAgents", []) if container else []
        exec_agent = next((a for a in agents if a["name"] == "ExecuteCommandAgent"), None)
        return exec_agent.get("lastStatus") if exec_agent else None

    _poll_until(
        _probe,
        lambda status: status == "RUNNING",
        timeout_s=30.0,
        interval_s=2.0,
    )


def _run_task_tolerating_role_propagation(ecs, *, cluster, task_def_arn, enable_execute_command):
    # A just-created task role is eventually consistent: ECS can transiently fail to
    # assume it for a short window after CreateRole/PutRolePolicy even once IAM's own
    # get_role already succeeds. Retry (bounded) on that specific error rather than
    # treating it as a real RunTask rejection.
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ecs.run_task(
                cluster=cluster,
                taskDefinition=task_def_arn,
                launchType="EC2",
                count=1,
                enableExecuteCommand=enable_execute_command,
            )
        except ClientError as exc:
            last_err = exc
            if "assume" not in str(exc).lower():
                raise
            time.sleep(5.0)
    raise AssertionError(f"RunTask never succeeded past IAM role propagation: {last_err}")


def _refusal(fn):
    """The Error of the ClientError ``fn`` raises; an unexpected success fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call unexpectedly succeeded")


def _outcome(fn):
    """The error code ``fn`` raises, or "succeeded" when it returns."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "succeeded"


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_cluster(cluster=cluster_arn)))
    return cluster_arn


def _register_container_instance(ctx, cluster_arn: str, doc: str, sig: str) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 4096},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 4096},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": []},
            {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
        ],
        versionInfo={"agentVersion": "1.0.0", "dockerVersion": "DockerVersion: 20.10.7"},
        # A real container agent self-reports these capabilities on registration;
        # without task-iam-role, RunTask refuses to place a task whose task def
        # carries a taskRoleArn, and without ecs.capability.execute-command it
        # refuses to place a task with enableExecuteCommand=True at all ("Container
        # instance lacks required attribute").
        attributes=[
            {"name": "com.amazonaws.ecs.capability.task-iam-role"},
            {"name": "ecs.capability.execute-command"},
        ],
    )
    arn = resp["containerInstance"]["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ecs.deregister_container_instance(
                cluster=cluster_arn, containerInstance=arn, force=True
            )
        )
    )
    return arn


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


def _launch_identity_source_instance(ctx):
    """Launch an EC2 instance with an SSM-capable instance profile and return its AWS-signed
    (identity_document_json, identity_document_signature) via SSM Run Command. Raises
    AssertionError (never skips) if a prerequisite such as IAM/SSM permissions is missing."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    except ClientError as exc:
        raise AssertionError(f"cannot describe the shared network: {exc}") from exc
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a real EC2 instance")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]

    role_name = ctx.unique_name("sim2real-ci-ssm-role-")
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
    except ClientError as exc:
        raise AssertionError(f"cannot create an IAM role for the identity-fetch instance: {exc}") from exc
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_role(RoleName=role_name)))
    ssm_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn))
    )
    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        )
    )

    # IAM role/instance-profile propagation lag before EC2 will accept it as a launch parameter.
    _poll_until(
        lambda: _outcome(lambda: iam.get_instance_profile(InstanceProfileName=profile_name)),
        lambda code: code == "succeeded",
        timeout_s=15.0,
        interval_s=2.0,
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    # A successful iam.get_instance_profile above only proves IAM's own view is
    # consistent -- EC2 caches instance profiles separately and can reject a
    # brand-new one with InvalidParameterValue for tens of seconds after IAM
    # already reports it. Retry on that specific EC2-side propagation error with
    # a deadline, not a fixed handful of attempts.
    instance_id = None
    last_err = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            reservation = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ci-identity-")}],
                    }
                ],
            )
            instance_id = reservation["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValue":
                raise
            time.sleep(5.0)
    if instance_id is None:
        raise AssertionError(f"could not launch the identity-fetch EC2 instance: {last_err}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _instance_state():
        # A just-launched instance ID can trail RunInstances by a few seconds before
        # DescribeInstances recognizes it -- EC2's own eventual consistency, not a
        # failed launch. Treat the transient NotFound as "not running yet" rather
        # than letting it escape the poll.
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
                "Name"
            ]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return "pending-visibility"
            raise

    _poll_until(
        _instance_state,
        lambda state: state == "running",
        timeout_s=60.0,
        interval_s=5.0,
    )

    def _ssm_ping_status():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])[
            "InstanceInformationList"
        ]
        return info[0]["PingStatus"] if info else None

    online = _poll_until(_ssm_ping_status, lambda status: status == "Online", timeout_s=120.0, interval_s=5.0)
    if online != "Online":
        raise AssertionError(f"identity-fetch EC2 instance never registered Online with SSM (status={online!r})")

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            # IMDSv2 (token-required) is the default hop-limit/enforcement posture for
            # current AL2023 AMIs -- an unauthenticated GET gets refused, not served.
            # Fetching a token first is also accepted when IMDSv1 is allowed, so this
            # works regardless of the instance's IMDS posture.
            "commands": [
                "TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "echo SIM2REAL_SPLIT",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
                "http://169.254.169.254/latest/dynamic/instance-identity/signature",
            ]
        },
    )["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError:
            return {"Status": "Pending"}

    invocation = _poll_until(
        _invocation,
        lambda inv: inv.get("Status") in ("Success", "Failed", "Cancelled", "TimedOut"),
        timeout_s=30.0,
        interval_s=3.0,
    )
    if invocation.get("Status") != "Success":
        raise AssertionError(f"identity-document SSM command did not succeed: {invocation.get('Status')!r}")

    doc_str, _, sig_str = invocation["StandardOutputContent"].partition("SIM2REAL_SPLIT")
    doc_str = doc_str.strip()
    sig_str = sig_str.strip()
    if not doc_str or not sig_str:
        raise AssertionError(
            "identity document/signature retrieval produced empty output: "
            f"stdout={invocation.get('StandardOutputContent')!r} "
            f"stderr={invocation.get('StandardErrorContent')!r}"
        )
    return doc_str, sig_str


def _create_task_role(ctx) -> str:
    # RunTask with enableExecuteCommand=True is itself refused by real ECS
    # (InvalidParameterException: "a valid task role is not being used") unless the
    # task definition carries a taskRoleArn -- the managed exec agent assumes that
    # role to talk to SSM. The positive control needs to clear this gate to reach
    # the boundary this check actually isolates.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ci-taskrole-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = "ecs-exec-ssmmessages"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ssmmessages:CreateControlChannel",
                            "ssmmessages:CreateDataChannel",
                            "ssmmessages:OpenControlChannel",
                            "ssmmessages:OpenDataChannel",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    # IAM role propagation lag, same as the instance-profile one above -- ECS can
    # transiently refuse a just-created role as "not a valid task role".
    _poll_until(
        lambda: _outcome(lambda: iam.get_role(RoleName=role_name)),
        lambda code: code == "succeeded",
        timeout_s=15.0,
        interval_s=2.0,
    )
    return role_arn


def _register_minimal_task_def(ctx, ecs, task_role_arn: str) -> str:
    family = ctx.unique_name("sim2real-behav-td-")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 128,
                "essential": True,
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
