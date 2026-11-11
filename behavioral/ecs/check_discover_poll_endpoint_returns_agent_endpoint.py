"""discover-poll-endpoint-returns-agent-endpoint."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "discover-poll-endpoint-returns-agent-endpoint"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DiscoverPollEndpoint returns a stable https endpoint/telemetryEndpoint pair for a registered instance."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Real AWS rejects RegisterContainerInstance without a genuine, AWS-signed EC2 instance
    # identity document ("The identity document and identity document signature were not
    # valid."). There is no way to forge one - provision a real EC2 instance and fetch its
    # signed document + signature from its own IMDS via SSM Run Command.
    ci_arn = _register_real_container_instance(ctx, ecs, cluster_arn)
    ctx.on_cleanup(
        lambda: ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn, force=True)
    )

    first = ecs.discover_poll_endpoint(cluster=cluster_arn, containerInstance=ci_arn)
    assert first["endpoint"].startswith("https://"), f"endpoint isn't an https URL: {first['endpoint']!r}"
    assert first["telemetryEndpoint"].startswith("https://"), (
        f"telemetryEndpoint isn't an https URL: {first['telemetryEndpoint']!r}"
    )
    assert first["endpoint"] != first["telemetryEndpoint"], "endpoint and telemetryEndpoint must not be identical"

    # Calling again for the same container instance must return the same pair (stable mapping).
    second = ecs.discover_poll_endpoint(cluster=cluster_arn, containerInstance=ci_arn)
    assert second["endpoint"] == first["endpoint"], "endpoint changed across repeated DiscoverPollEndpoint calls"
    assert second["telemetryEndpoint"] == first["telemetryEndpoint"], (
        "telemetryEndpoint changed across repeated DiscoverPollEndpoint calls"
    )


def _register_real_container_instance(ctx, ecs, cluster_arn: str) -> str:
    identity = _provision_signed_container_instances(ctx, count=1)[0]
    resp = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=identity["identity_document"],
        instanceIdentityDocumentSignature=identity["identity_document_signature"],
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 2048},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 4096},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": ["22", "2375", "2376", "51678", "51679"]},
            {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
        ],
        versionInfo={
            "agentVersion": "1.0.0",
            "agentHash": "0" * 40,
            "dockerVersion": "DockerVersion: 1.0.0",
        },
    )
    return resp["containerInstance"]["containerInstanceArn"]


def _deregister_best_effort(ecs, cluster_name, ci_arn):
    from botocore.exceptions import ClientError

    try:
        ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn)
    except ClientError:
        pass


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _terminate_instances_best_effort(ec2, instance_ids):
    from botocore.exceptions import ClientError

    try:
        ec2.terminate_instances(InstanceIds=instance_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _detach_policy_best_effort(iam, role_name, policy_arn):
    from botocore.exceptions import ClientError

    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _remove_role_from_profile_best_effort(iam, profile_name, role_name):
    from botocore.exceptions import ClientError

    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile_best_effort(iam, profile_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_best_effort(iam, role_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _provision_signed_container_instances(ctx, count):
    """Launch `count` real EC2 instances (with an SSM-managed instance role) and use SSM Run
    Command to fetch each one's genuine, AWS-signed instance-identity document + signature from
    its own IMDS. Returns a list of dicts with instance_id/identity_document/
    identity_document_signature, one per instance."""
    from botocore.exceptions import ClientError

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

    role_name = ctx.unique_name("sim2real-ci-ssm-")
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
