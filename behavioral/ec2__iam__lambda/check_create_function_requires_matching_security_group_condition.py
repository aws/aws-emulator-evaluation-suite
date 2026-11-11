"""create-function-requires-matching-security-group-condition."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-function-requires-matching-security-group-condition"
GROUP = "condition-keys"
SERVICES = ["ec2", "iam", "lambda"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, done, *, timeout_s, interval_s=2.0, what):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s:.0f}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _release_enis(ec2, vpc_id, *, budget_s=540.0, interval_s=10.0):
    """Delete every lambda-managed ENI left in ``vpc_id`` once it goes ``available``.

    Lambda detaches its Hyperplane ENI asynchronously after DeleteFunction; a VPC/subnet/SG
    delete issued too early fails DependencyViolation, so this polls and reaps them first. A
    freshly 'available' ENI can still answer DeleteNetworkInterface with "currently in use" for a
    few more seconds, so that one error is retried rather than treated as fatal.
    """
    deadline = time.monotonic() + budget_s
    while True:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]
        if not enis:
            return
        for eni in enis:
            if eni["Status"] == "available":
                try:
                    ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code not in ("InvalidNetworkInterfaceID.NotFound", "InvalidParameterValue"):
                        raise
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"ENI(s) in {vpc_id} did not release within {budget_s}s: {enis!r}")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role whose policy allows lambda:CreateFunction and lambda:UpdateFunctionConfiguration
    only when every lambda:SecurityGroupIds value is one allowed security group is denied a VPC
    config naming another group, and allowed the identical request naming the allowed one.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))

    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert azs, "no available AZ in this region"
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.91.1.0/24",
                                   AvailabilityZone=azs[0], TagSpecifications=[
        {"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    sg_allowed = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-condkey-sg-allowed-"), Description="allowed",
        VpcId=vpc_id, TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_security_group(GroupId=sg_allowed),
                             "InvalidGroup.NotFound"))
    sg_other = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-condkey-sg-other-"), Description="other",
        VpcId=vpc_id, TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_security_group(GroupId=sg_other),
                             "InvalidGroup.NotFound"))

    exec_role_name = ctx.unique_name("sim2real-condkey-exec-")
    exec_role_arn = iam.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=exec_role_name), "NoSuchEntity"))
    exec_policies = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                     "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"]
    for policy_arn in exec_policies:
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(_teardown(
            lambda policy_arn=policy_arn: iam.detach_role_policy(RoleName=exec_role_name,
                                                                  PolicyArn=policy_arn),
            "NoSuchEntity"))

    whoami = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in whoami:
        trust_principal = f"arn:aws:iam::{ctx.account}:role/{whoami.split(':assumed-role/')[1].split('/')[0]}"
    else:
        trust_principal = whoami

    caller_role_name = ctx.unique_name("sim2real-condkey-caller-")
    caller_role_arn = iam.create_role(
        RoleName=caller_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": trust_principal},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=caller_role_name), "NoSuchEntity"))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn},
            {"Effect": "Allow", "Action": ["ec2:DescribeSecurityGroups", "ec2:DescribeSubnets",
                                           "ec2:DescribeVpcs", "ec2:GetSecurityGroupsForVpc"],
             "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"],
                "Resource": "*",
                "Condition": {"ForAllValues:StringEquals": {"lambda:SecurityGroupIds": [sg_allowed]}},
            },
        ],
    }
    iam.put_role_policy(RoleName=caller_role_name, PolicyName="sim2real-condition",
                        PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=caller_role_name, PolicyName="sim2real-condition"),
        "NoSuchEntity"))

    def assumed_lambda_client():
        creds = sts.assume_role(RoleArn=caller_role_arn, RoleSessionName="probe")["Credentials"]
        return ctx.client("lambda", creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        })

    # The allowed request runs first: its success shows the inline policy has propagated, so the
    # denial that follows comes from the condition, not from a policy not yet in effect.
    allowed_name = ctx.unique_name("sim2real-condkey-fn-allowed-")

    def _try_allowed():
        try:
            assumed = assumed_lambda_client()
            return assumed.create_function(
                FunctionName=allowed_name, Runtime="python3.12", Handler="index.handler",
                Role=exec_role_arn, Code={"ZipFile": _zip("def handler(e,c): return 1")},
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_allowed]})
        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "AccessDenied", "AccessDeniedException", "InvalidParameterValueException",
                "UnrecognizedClientException",
            ):
                return None
            raise

    # Registered in reverse of the order they must run: cleanup is LIFO, and the VPC/SG/subnet
    # deletes above cannot proceed until the function's ENI detaches, so the ENI reap is
    # registered FIRST (runs LAST), then the log group, then the function delete (runs FIRST).
    ctx.on_cleanup(lambda: _release_enis(ec2, vpc_id))
    ctx.on_cleanup(lambda: _delete_log_group(ctx, allowed_name))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=allowed_name),
                             "ResourceNotFoundException"))
    created = _poll(ctx, _try_allowed, lambda r: r is not None, timeout_s=120,
                    what="CreateFunction with the matching SecurityGroupIds is allowed")
    assert created["FunctionName"] == allowed_name, (
        f"CreateFunction with the matching condition value returned {created!r}")
    lam.tag_resource(Resource=created["FunctionArn"], Tags={"sim2real": CHECK})
    cfg = lam.get_function_configuration(FunctionName=allowed_name)
    assert sorted(cfg["VpcConfig"]["SecurityGroupIds"]) == [sg_allowed], (
        f"the created function's VpcConfig carries {cfg['VpcConfig']['SecurityGroupIds']!r}, "
        f"expected only {sg_allowed!r}")

    denied_name = ctx.unique_name("sim2real-condkey-fn-denied-")
    expected_denied_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{denied_name}"
    expected_caller_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{caller_role_name}/probe"
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=denied_name),
                             "ResourceNotFoundException"))

    def _probe_without_match():
        try:
            assumed = assumed_lambda_client()
            assumed.create_function(
                FunctionName=denied_name, Runtime="python3.12", Handler="index.handler",
                Role=exec_role_arn, Code={"ZipFile": _zip("def handler(e,c): return 1")},
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_other]})
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err["Message"]
        raise AssertionError(
            "CreateFunction naming the non-allowed security group was expected to be refused "
            "but it SUCCEEDED")

    # A just-issued session's credentials can briefly be unrecognized (UnrecognizedClientException)
    # and sts:AssumeRole can briefly answer AccessDenied; neither is Lambda's AccessDeniedException,
    # so only those retry.
    _retryable = ("AccessDenied", "UnrecognizedClientException")
    code, message = _poll(ctx, _probe_without_match, lambda r: r[0] not in _retryable,
                          timeout_s=90, what="the caller session propagates through STS")
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
    assert message == (
        f"User: {expected_caller_arn} is not authorized to perform: lambda:CreateFunction on "
        f"resource: {expected_denied_arn} because no identity-based policy allows the "
        "lambda:CreateFunction action"
    ), f"unexpected AccessDenied message: {message!r}"


def _delete_log_group(ctx, function_name):
    """The log group a successful CreateFunction may not have created yet; absence is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
