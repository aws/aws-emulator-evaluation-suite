"""update-container-agent-triggers-update-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-container-agent-triggers-update-state"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterContainerInstance with a genuine identity document is ACTIVE and agentConnected but drops the
    client-supplied versionInfo, so UpdateContainerAgent is refused with "Unknown current version" and the
    instance's agentUpdateStatus does not change.
    """
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    identity = _provision_signed_container_instances(ctx, count=1)[0]
    claimed_version_info = {
        "agentVersion": "1.0.0",
        "agentHash": "0" * 40,
        "dockerVersion": "DockerVersion: 1.0.0",
    }
    reg = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=identity["identity_document"],
        instanceIdentityDocumentSignature=identity["identity_document_signature"],
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 2048},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 4096},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": ["22", "2375", "2376", "51678", "51679"]},
            {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
        ],
        versionInfo=claimed_version_info,
    )["containerInstance"]
    ci_arn = reg["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn, force=True)
    )

    assert reg.get("status") == "ACTIVE", f"expected the manual registration itself to succeed as ACTIVE, got {reg.get('status')!r}"
    assert reg.get("agentConnected") is True, (
        f"expected agentConnected True on the strength of the genuine signed identity document alone, "
        f"got {reg.get('agentConnected')!r}"
    )
    assert not reg.get("versionInfo"), (
        f"expected RegisterContainerInstance to discard the client-supplied versionInfo "
        f"{claimed_version_info!r}, got it echoed back as {reg.get('versionInfo')!r}"
    )

    before = _poll_until(
        lambda: ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])[
            "containerInstances"
        ],
        lambda instances: len(instances) == 1,
        timeout_s=30.0,
        interval_s=3.0,
    )[0]
    assert not before.get("versionInfo"), (
        f"expected an independent DescribeContainerInstances read to confirm the discarded versionInfo, "
        f"got {before.get('versionInfo')!r}"
    )
    before_status = before.get("agentUpdateStatus")

    refusal_codes = {"MissingVersionException", "ClientException"}
    try:
        ecs.update_container_agent(cluster=cluster_arn, containerInstance=ci_arn)
        raise AssertionError(
            "UpdateContainerAgent unexpectedly succeeded against a container instance with no "
            "server-recorded agent version"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code in refusal_codes, (
            f"expected one of {sorted(refusal_codes)} for a container instance with no server-recorded "
            f"agent version, got {code!r}: {message!r}"
        )
        assert message == "Unknown current version", f"expected 'Unknown current version', got {message!r}"

    after = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])["containerInstances"][
        0
    ]
    assert after.get("agentUpdateStatus") == before_status, (
        f"agentUpdateStatus should not have transitioned on a refused update: "
        f"before={before_status!r} after={after.get('agentUpdateStatus')!r}"
    )


def _terminate_instances_best_effort(ec2, instance_ids):
    try:
        ec2.terminate_instances(InstanceIds=instance_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _detach_policy_best_effort(iam, role_name, policy_arn):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _remove_role_from_profile_best_effort(iam, profile_name, role_name):
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile_best_effort(iam, profile_name):
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_best_effort(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _provision_signed_container_instances(ctx, count):
    """Launch `count` real EC2 instances (with an SSM-managed instance role) and use SSM Run
    Command to fetch each one's genuine, AWS-signed instance-identity document + signature from
    its own IMDS. Returns a list of dicts with instance_id/identity_document/
    identity_document_signature, one per instance."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("unreachable: no shared network VPC subnets available to launch a real EC2 instance")
    subnet_id = subnets[0]["SubnetId"]
    vpc_id = subnets[0]["VpcId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("unreachable: no default security group available in the shared network")
    sg_id = sgs[0]["GroupId"]

    role_name = ctx.unique_name("sim2real-uca-ssm-")
    profile_name = role_name
    trust = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    )
    ssm_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    try:
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
        ctx.on_cleanup(lambda: _delete_role_best_effort(iam, role_name))
        iam.attach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn)
        ctx.on_cleanup(lambda: _detach_policy_best_effort(iam, role_name, ssm_policy_arn))
        iam.create_instance_profile(InstanceProfileName=profile_name)
        ctx.on_cleanup(lambda: _delete_instance_profile_best_effort(iam, profile_name))
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        ctx.on_cleanup(lambda: _remove_role_from_profile_best_effort(iam, profile_name, role_name))
    except ClientError as err:
        raise AssertionError(f"unreachable: cannot provision the SSM instance role ({err.response['Error']['Code']})")

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]

    deadline = time.monotonic() + 90.0
    instance_ids = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=count,
                MaxCount=count,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": role_name}]}],
            )
            instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            last_err = err
            # a freshly-created instance profile isn't immediately usable by EC2 (IAM propagation)
            if code in ("InvalidParameterValue", "InvalidParameterCombination") and "profile" in str(err).lower():
                time.sleep(5)
                continue
            raise
    if instance_ids is None:
        raise AssertionError(
            f"unreachable: RunInstances never succeeded after IAM instance-profile propagation retries: {last_err}"
        )
    ctx.on_cleanup(lambda: _terminate_instances_best_effort(ec2, instance_ids))

    def _online_ids():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": instance_ids}])[
            "InstanceInformationList"
        ]
        return {i["InstanceId"] for i in info if i.get("PingStatus") == "Online"}

    online = _poll_until(
        _online_ids,
        lambda ids: len(ids) == len(instance_ids),
        timeout_s=180.0,
        interval_s=8.0,
    )

    script = (
        "TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token "
        "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'); "
        "echo ---DOC-START---; "
        "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/dynamic/instance-identity/document; "
        "echo ---DOC-END---; "
        "echo ---SIG-START---; "
        "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/dynamic/instance-identity/signature; "
        "echo ---SIG-END---"
    )
    send_resp = ssm.send_command(
        InstanceIds=list(online), DocumentName="AWS-RunShellScript", Parameters={"commands": [script]}
    )
    command_id = send_resp["Command"]["CommandId"]

    results = {}
    for instance_id in online:
        def _invocation(iid=instance_id):
            try:
                return ssm.get_command_invocation(CommandId=command_id, InstanceId=iid)
            except ClientError:
                return {"Status": "Pending"}

        inv = _poll_until(
            _invocation,
            lambda r: r.get("Status") in ("Success", "Failed", "Cancelled", "TimedOut"),
            timeout_s=60.0,
            interval_s=5.0,
        )
        if inv.get("Status") != "Success":
            raise AssertionError(
                f"unreachable: could not retrieve the instance identity document via SSM ({inv.get('Status')})"
            )
        out = inv["StandardOutputContent"]
        doc = out.split("---DOC-START---")[1].split("---DOC-END---")[0].strip()
        sig = out.split("---SIG-START---")[1].split("---SIG-END---")[0].strip()
        results[instance_id] = {
            "instance_id": instance_id,
            "identity_document": doc,
            "identity_document_signature": sig,
        }

    return [results[i] for i in instance_ids]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

