"""container-instance-deregister-removes-from-list."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "container-instance-deregister-removes-from-list"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deregistered container instance disappears from ListContainerInstances."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ci-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Real AWS rejects RegisterContainerInstance without a genuine, AWS-signed EC2 instance
    # identity document ("The identity document and identity document signature were not
    # valid."). There is no way to forge one — provision two real EC2 instances and use SSM Run
    # Command to fetch each one's signed document + signature from its own IMDS.
    identities = _provision_signed_container_instances(ctx, count=2)

    # Real AWS rejects RegisterContainerInstance with "Resources can not be null or have null
    # elements" unless totalResources is populated the way the real ECS agent populates it
    # (CPU/MEMORY/PORTS/PORTS_UDP) — it isn't defaulted to an empty list server-side.
    total_resources = [
        {"name": "CPU", "type": "INTEGER", "integerValue": 4096},
        {"name": "MEMORY", "type": "INTEGER", "integerValue": 7982},
        {"name": "PORTS", "type": "STRINGSET", "stringSetValue": ["22", "2375", "2376", "51678", "51679"]},
        {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
    ]

    ci_arn_a = ecs.register_container_instance(
        cluster=cluster_name,
        instanceIdentityDocument=identities[0]["identity_document"],
        instanceIdentityDocumentSignature=identities[0]["identity_document_signature"],
        totalResources=total_resources,
    )["containerInstance"]["containerInstanceArn"]
    ctx.on_cleanup(lambda: _deregister_best_effort(ecs, cluster_name, ci_arn_a))
    ci_arn_b = ecs.register_container_instance(
        cluster=cluster_name,
        instanceIdentityDocument=identities[1]["identity_document"],
        instanceIdentityDocumentSignature=identities[1]["identity_document_signature"],
        totalResources=total_resources,
    )["containerInstance"]["containerInstanceArn"]
    ctx.on_cleanup(lambda: _deregister_best_effort(ecs, cluster_name, ci_arn_b))

    # ListContainerInstances lags slightly behind RegisterContainerInstance on real AWS; poll
    # (bounded) instead of asserting on the very next call.
    listed = _poll_until(
        lambda: set(ecs.list_container_instances(cluster=cluster_name)["containerInstanceArns"]),
        lambda s: ci_arn_a in s and ci_arn_b in s,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert ci_arn_a in listed and ci_arn_b in listed, "both freshly registered instances must be listed"

    ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn_a)

    listed_after = _poll_until(
        lambda: set(ecs.list_container_instances(cluster=cluster_name)["containerInstanceArns"]),
        lambda s: ci_arn_a not in s,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert ci_arn_a not in listed_after, "deregistered instance must be absent from ListContainerInstances"
    assert ci_arn_b in listed_after, "the untouched sibling instance must remain listed"


def _deregister_best_effort(ecs, cluster_name, ci_arn):
    from botocore.exceptions import ClientError

    try:
        ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
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


def _terminate_instances_best_effort(ec2, instance_ids):
    from botocore.exceptions import ClientError

    try:
        ec2.terminate_instances(InstanceIds=instance_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


_EC2_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ci-dereg"},
]


def _dedicated_network(ctx, ec2):
    """Provision a small, dedicated VPC for the identity-source EC2 instances instead of
    depending on an ambient default VPC, which a freshly provisioned account may not have."""
    from botocore.exceptions import ClientError

    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _EC2_TAGS}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.198.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _EC2_TAGS}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _EC2_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        eni_deadline = time.monotonic() + 300
        while time.monotonic() < eni_deadline:
            enis = ec2.describe_network_interfaces(Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]).get(
                "NetworkInterfaces", []
            )
            if not enis:
                break
            time.sleep(2)

        subnet_deadline = time.monotonic() + 180
        while True:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "InvalidSubnetID.NotFound":
                    break
                if code != "DependencyViolation" or time.monotonic() >= subnet_deadline:
                    raise
                time.sleep(2)

        try:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] not in (
                "Gateway.NotAttached",
                "InvalidInternetGatewayID.NotFound",
            ):
                raise
        try:
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInternetGatewayID.NotFound":
                raise

        vpc_deadline = time.monotonic() + 180
        while True:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "InvalidVpcID.NotFound":
                    break
                if code != "DependencyViolation" or time.monotonic() >= vpc_deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


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

    subnet_id, sg_id = _dedicated_network(ctx, ec2)

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

