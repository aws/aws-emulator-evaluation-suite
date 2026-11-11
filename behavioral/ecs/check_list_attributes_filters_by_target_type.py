"""list-attributes-filters-by-target-type."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-attributes-filters-by-target-type"
GROUP = "ordering"
SERVICES = ["ecs"]


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAttributes(targetType="container-instance") returns exactly the container-instance
    attributes with the requested name; any other targetType value is rejected."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ecs-attrfilt-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # RegisterContainerInstance requires an AWS-signed identity document, so two real
    # instances are launched and their documents fetched via SSM Run Command.
    identities = _provision_signed_container_instances(ctx, count=2)
    total_resources = [
        {"name": "CPU", "type": "INTEGER", "integerValue": 4096},
        {"name": "MEMORY", "type": "INTEGER", "integerValue": 7982},
        {"name": "PORTS", "type": "STRINGSET", "stringSetValue": ["22", "2375", "2376", "51678", "51679"]},
        {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
    ]

    ci_arns = []
    for identity in identities:
        reg = ecs.register_container_instance(
            cluster=cluster_name,
            instanceIdentityDocument=identity["identity_document"],
            instanceIdentityDocumentSignature=identity["identity_document_signature"],
            totalResources=total_resources,
        )
        ci_arns.append(reg["containerInstance"]["containerInstanceArn"])
    ctx.on_cleanup(
        lambda: [
            ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=a, force=True)
            for a in ci_arns
        ]
    )

    attr_name = ctx.unique_name("sim2real-kind-")
    # A just-registered instance can briefly draw TargetNotFoundException from PutAttributes.
    _put_attributes_with_retry(
        ecs,
        cluster=cluster_arn,
        attributes=[
            {"name": attr_name, "value": "A", "targetId": ci_arns[0]},
            {"name": attr_name, "value": "B", "targetId": ci_arns[1]},
        ],
    )

    # ListAttributes is eventually consistent after PutAttributes, so poll for both attributes.
    listed = _poll_until(
        lambda: ecs.list_attributes(
            cluster=cluster_arn, targetType="container-instance", attributeName=attr_name
        )["attributes"],
        lambda attrs: {a["targetId"] for a in attrs} == set(ci_arns),
        timeout_s=30.0,
        interval_s=2.0,
    )
    by_target = {a["targetId"]: a["value"] for a in listed}
    assert set(by_target.keys()) == set(ci_arns), (
        f"ListAttributes returned unexpected target set {set(by_target)} vs {set(ci_arns)}"
    )
    assert by_target[ci_arns[0]] == "A", f"expected value 'A' for {ci_arns[0]}, got {by_target[ci_arns[0]]!r}"
    assert by_target[ci_arns[1]] == "B", f"expected value 'B' for {ci_arns[1]}, got {by_target[ci_arns[1]]!r}"
    # ListAttributes returns only name/value/targetId per attribute, without targetType.
    for a in listed:
        assert "targetType" not in a, f"expected no per-attribute targetType field, got {a.get('targetType')!r}"
        assert a["targetId"] in ci_arns, f"unexpected targetId {a['targetId']!r} not in {ci_arns}"

    # container-instance is the only valid targetType value.
    error = _error(
        lambda: ecs.list_attributes(
            cluster=cluster_arn, targetType="task-definition", attributeName=attr_name
        )
    )
    expected = ("InvalidParameterException", "Unexpected targetType 'task-definition'.")
    assert error == expected, f"expected {expected!r}, got {error!r}"



def _put_attributes_with_retry(ecs, timeout_s=30.0, interval_s=2.0, **kwargs):
    """PutAttributes, retrying only TargetNotFoundException (bounded) while a just-registered
    container instance propagates; any other error raises immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ecs.put_attributes(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TargetNotFoundException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
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
    """Launch `count` EC2 instances and fetch each one's AWS-signed identity document and
    signature via SSM Run Command; returns one dict per instance."""
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

    role_name = ctx.unique_name("sim2real-attrfilt-ssm-")
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

