"""submit-container-state-change-updates-container-status."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "submit-container-state-change-updates-container-status"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SubmitContainerStateChange (agent-facing) updates the per-container
    status/exitCode inside a RunTask-created task, visible in DescribeTasks' containers
    list, independently of the overall task-level lastStatus.
    """
    ecs = ctx.client("ecs")

    cluster_arn = _create_cluster(ctx)
    # Real AWS cryptographically validates the instance identity document/signature pair
    # on RegisterContainerInstance and rejects an omitted (or synthetic) pair with
    # InvalidParameterException ("...were not valid"). Provision a real, running EC2
    # instance and pull ITS genuine, AWS-signed identity document/signature via SSM Run
    # Command so the registration is actually accepted.
    doc, sig = _launch_identity_source_instance(ctx)
    _register_container_instance(ctx, cluster_arn, doc, sig)
    task_def_arn = _register_minimal_task_def(ctx, ecs)


    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="EC2",
        count=1,
    )
    assert not run_resp.get("failures"), f"RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.submit_task_state_change(cluster=cluster_arn, task=task_arn, status="STOPPED"))
    )

    initial_containers = run_resp["tasks"][0].get("containers", [])
    initial_app = next((c for c in initial_containers if c["name"] == "app"), None)
    if initial_app is not None:
        assert initial_app.get("lastStatus") != "STOPPED", "container already STOPPED before we reported it"

    ecs.submit_container_state_change(
        cluster=cluster_arn,
        task=task_arn,
        containerName="app",
        status="STOPPED",
        exitCode=1,
        reason="sim2real-behav: simulated agent-reported container exit",
    )

    def _get_app_container():
        t = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
        return next((c for c in t.get("containers", []) if c["name"] == "app"), None)

    final_container = _poll_until(
        _get_app_container,
        lambda c: c is not None and c.get("lastStatus") == "STOPPED",
        timeout_s=30.0,
    )
    assert final_container is not None, "container 'app' lastStatus never became STOPPED via SubmitContainerStateChange"
    assert final_container["lastStatus"] == "STOPPED", (
        f"expected lastStatus STOPPED, got {final_container['lastStatus']!r}"
    )
    assert final_container.get("exitCode") == 1, f"expected exitCode 1, got {final_container.get('exitCode')}"


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "ClusterNotFoundException"
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if last is not None and predicate(last) else None


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


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


def _instance_profile_visible(iam, profile_name: str) -> bool:
    """True once GetInstanceProfile resolves *profile_name*; False while IAM still reports
    NoSuchEntity; any other error propagates."""
    try:
        iam.get_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise
    return True


def _launch_identity_source_instance(ctx):
    """Launch a genuine EC2 instance behind an SSM-capable instance profile and pull ITS real,
    AWS-signed instance-identity document + signature via SSM Run Command. Returns
    (identity_document_json, identity_document_signature). Registers cleanup for every resource
    it creates; raises AssertionError if a prerequisite (shared network, IAM/SSM permissions) isn't
    available in this account."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    except ClientError as exc:
        raise AssertionError(f"cannot describe the shared network: {exc}")
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
        raise AssertionError(f"cannot create an IAM role for the identity-fetch instance: {exc}")
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
        lambda: _instance_profile_visible(iam, profile_name),
        lambda visible: visible,
        timeout_s=15.0,
        interval_s=2.0,
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    # IAM instance-profile propagation to EC2 lags behind the profile's own visibility in IAM
    # (the poll above) by up to ~90s on real AWS; RunInstances rejects the profile with
    # InvalidParameterValue ("Invalid IAM Instance Profile name") until it catches up.
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
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            last_err = exc
            if code != "InvalidParameterValue" or "Instance Profile" not in message:
                raise
            time.sleep(5.0)
    if instance_id is None:
        raise AssertionError(f"could not launch the identity-fetch EC2 instance: {last_err}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _instance_state():
        # RunInstances's own instance id is not always immediately visible to DescribeInstances
        # (a read-after-write race on a resource this check just created); treat that as "not
        # ready yet", not a hard failure.
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
                "Name"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return None
            raise

    state = _poll_until(_instance_state, lambda s: s == "running", timeout_s=45.0, interval_s=5.0)
    if state != "running":
        raise AssertionError(f"identity-fetch EC2 instance never reached running (state={state!r})")

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
            "commands": [
                # IMDSv2 (token-gated) is the account default on new instances; IMDSv1-style
                # GETs come back 401 with an empty body once it's enforced, so fetch a token first.
                'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" '
                '-H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
                'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "echo SIM2REAL_SPLIT",
                'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
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
        raise AssertionError("identity document/signature retrieval produced empty output")
    return doc_str, sig_str


def _register_minimal_task_def(ctx, ecs) -> str:
    family = ctx.unique_name("sim2real-behav-td-")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["EC2"],
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
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    ctx.on_cleanup(lambda: _safe(lambda: ecs.deregister_task_definition(taskDefinition=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
