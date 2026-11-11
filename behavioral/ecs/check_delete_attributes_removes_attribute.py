"""delete-attributes-removes-attribute."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-attributes-removes-attribute"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAttributes sets a custom attribute; DeleteAttributes removes it so it
    no longer shows up in ListAttributes, while the cluster/instance stay intact."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ecs-attrcl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Real AWS rejects RegisterContainerInstance without a genuine, AWS-signed EC2 instance
    # identity document ("The identity document and identity document signature must both be
    # specified."). There is no way to forge one -- provision a real EC2 instance and fetch its
    # signed document + signature from its own IMDS via SSM Run Command.
    identity = _provision_signed_container_instances(ctx, count=1)[0]

    reg = ecs.register_container_instance(
        cluster=cluster_name,
        instanceIdentityDocument=identity["identity_document"],
        instanceIdentityDocumentSignature=identity["identity_document_signature"],
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 4096},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 7982},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": ["22", "2375", "2376", "51678", "51679"]},
            {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
        ],
    )
    ci_arn = reg["containerInstance"]["containerInstanceArn"]

    def _cleanup_ci():
        ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn, force=True)

    ctx.on_cleanup(_cleanup_ci)

    # RegisterContainerInstance can return before the new instance is consistently visible
    # elsewhere in the control plane: a fresh instance has been observed to 404 out of
    # DescribeContainerInstances and PutAttributes for tens of seconds. Bound both the
    # visibility check and the write with a deadline instead of assuming immediate consistency.
    reg_deadline = time.monotonic() + 30
    while True:
        described_ci = ecs.describe_container_instances(
            cluster=cluster_arn, containerInstances=[ci_arn]
        )["containerInstances"]
        if described_ci:
            break
        if time.monotonic() >= reg_deadline:
            raise AssertionError(f"container instance {ci_arn} never became describable within 30s")
        time.sleep(2)

    attr_name = "sim2real-marker"
    put_deadline = time.monotonic() + 30
    while True:
        try:
            ecs.put_attributes(
                cluster=cluster_arn,
                attributes=[{"name": attr_name, "value": "v1", "targetId": ci_arn}],
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "TargetNotFoundException" or time.monotonic() >= put_deadline:
                raise
            time.sleep(2)

    listed = None
    list_deadline = time.monotonic() + 30
    while time.monotonic() < list_deadline:
        listed = ecs.list_attributes(
            cluster=cluster_arn, targetType="container-instance", attributeName=attr_name
        )["attributes"]
        if len(listed) == 1:
            break
        time.sleep(2)
    assert listed is not None and len(listed) == 1, f"expected exactly 1 attribute named {attr_name!r}, got {listed}"
    assert listed[0]["targetId"] == ci_arn, f"expected targetId {ci_arn}, got {listed[0]['targetId']}"
    assert listed[0]["value"] == "v1", f"expected value 'v1', got {listed[0]['value']!r}"

    ecs.delete_attributes(
        cluster=cluster_arn,
        attributes=[{"name": attr_name, "targetId": ci_arn}],
    )

    deadline = time.monotonic() + 30
    remaining = None
    while time.monotonic() < deadline:
        remaining = ecs.list_attributes(
            cluster=cluster_arn, targetType="container-instance", attributeName=attr_name
        )["attributes"]
        if len(remaining) == 0:
            break
        time.sleep(1.5)
    assert remaining == [], f"attribute {attr_name!r} still present after DeleteAttributes: {remaining}"

    # The container instance itself is untouched -- only the attribute was removed.
    described = ecs.describe_container_instances(
        cluster=cluster_arn, containerInstances=[ci_arn]
    )["containerInstances"]
    assert len(described) == 1, f"expected exactly 1 container instance for {ci_arn}, got {described}"
    assert described[0]["containerInstanceArn"] == ci_arn, (
        f"expected describe_container_instances to return {ci_arn}, got {described[0]['containerInstanceArn']}"
    )


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

    role_name = ctx.unique_name("sim2real-attr-ssm-")
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
