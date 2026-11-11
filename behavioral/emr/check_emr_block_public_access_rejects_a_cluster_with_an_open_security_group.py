"""emr-block-public-access-rejects-a-cluster-with-an-open-security-group."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "emr-block-public-access-rejects-a-cluster-with-an-open-security-group"
GROUP = 'errors'
SERVICES = ['emr']

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

# Not 22: it is in AWS's default exception list, so a rule on 22 would be permitted.
_OPEN_PORT = 1234
_SSH_PORT = 22

_SCENARIO = "emr-block-public-access"
_TAGS = [{"Key": "sim2real", "Value": _SCENARIO},
         {"Key": "sim2real:managed", "Value": "true"},
         {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")
_CLUSTER_SETTLED = {"RUNNING", "WAITING", "TERMINATED", "TERMINATED_WITH_ERRORS"}


def _swallow(fn):
    """Teardown call: a cluster already gone (ValidationException "Specified job flow ID not valid")
    counts as terminated, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the check's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the check's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts=60, delay=2):
    """Run an IAM delete, retrying DeleteConflict."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _delete_sg_with_retry(ec2, sg, attempts=180, delay=2):
    """Delete the security group, retrying DependencyViolation.

    A cluster's ENIs keep referencing the group for a while after the cluster is gone.
    """
    for i in range(attempts):
        try:
            ec2.delete_security_group(GroupId=sg)
            return
        except Exception as exc:  # noqa: BLE001
            if "DependencyViolation" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile. Returns (service_role, ec2_role)."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-bpa-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-bpa-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # No fixed wait for IAM propagation here: _run_cluster already retries RunJobFlow, bounded,
    # on the exact "invalid instanceprofile" / "invalid ec2" errors propagation delay produces.
    return svc_role, ec2_role


def _pick_vpc_and_subnet(ctx):
    """A shared network and a subnet in an AZ that actually offers INSTANCE_TYPE.

    describe_instance_type_offerings ignores zone state and describe_availability_zones ignores
    instance types, so both are consulted.
    """
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "the account has no shared network VPC, so EMR has nowhere to place the cluster"
    vpc = vpcs[0]["VpcId"]
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]} & offered
    assert usable, (
        f"no available AZ in {ctx.region} offers {INSTANCE_TYPE}; offerings were "
        f"{sorted(offered)!r}"
    )
    subnets = [s for page in ec2.get_paginator("describe_subnets").paginate(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
        for s in page["Subnets"] if s["AvailabilityZone"] in usable]
    assert subnets, (
        f"shared network VPC {vpc} has no subnet in an AZ offering {INSTANCE_TYPE} ({sorted(usable)!r})"
    )
    return vpc, sorted(s["SubnetId"] for s in subnets)[0]


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id):
    """Terminate the cluster and WAIT for the termination to finish, so the IAM deletions
    registered earlier (and therefore running later, LIFO) do not race a live cluster."""
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    last = None
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(2)
            continue
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        last = state
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {last!r}")


def _run_cluster(emr, ctx, **params):
    """RunJobFlow, retrying only transient IAM-propagation and throttle errors, with teardown
    registered as soon as the cluster id exists."""
    deadline = time.monotonic() + _budget_s(ctx, 320.0)
    while True:
        try:
            resp = emr.run_job_flow(**params)
            break
        except Exception as exc:  # noqa: BLE001
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient:
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("RunJobFlow outlasting IAM propagation and throttling: the "
                                       "run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id))
    return cluster_id


def _instances(emr, cluster_id):
    """Every instance the cluster has, paginated -- membership on page one is not membership."""
    return [i for page in emr.get_paginator("list_instances").paginate(ClusterId=cluster_id)
            for i in page.get("Instances", [])]


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c3", "cap:c5", "resource:account-singleton:emr-block-public-access")
def run(ctx) -> None:
    """With block public access on and port 1234 not excepted, a cluster whose group is open to
    ::/0 on 1234 ends with VALIDATION_ERROR and no EC2 instances; once 1234 is permitted the
    identical launch provisions instances.

    Reference: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-block-public-access.html
    """
    ctx.on_cleanup(lambda: _delete_emr_default_security_groups(ctx))
    emr = ctx.client("emr")
    ec2 = ctx.client("ec2")

    # Stash the account's configuration FIRST and register its restore, so the singleton is put
    # back even if setup below fails.
    prior = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    prior_ranges = prior.get("PermittedPublicSecurityGroupRuleRanges", [])
    ctx.on_cleanup(lambda: emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": prior["BlockPublicSecurityGroupRules"],
            "PermittedPublicSecurityGroupRuleRanges": prior_ranges}))

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    vpc, subnet = _pick_vpc_and_subnet(ctx)

    # The open group. EMR needs a companion group for the core nodes when the check supplies the
    # EMR-managed groups itself, and it is created first so LIFO deletes it last.
    open_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-emr-bpa-open-"),
        Description="sim2real-behav emr block-public-access check: deliberately open group",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}])["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_with_retry(ec2, open_sg))
    ec2.authorize_security_group_ingress(
        GroupId=open_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _OPEN_PORT, "ToPort": _OPEN_PORT,
                        # open-ingress-subject: EMR block public access refuses only a rule open
                        # to 0.0.0.0/0 or ::/0, so a narrower range leaves nothing to refuse. The
                        # rule is ::/0 on an IPv4-only VPC, so no instance has an address it admits.
                        "Ipv6Ranges": [{"CidrIpv6": "::/0",
                                        "Description": "sim2real-behav deliberately public"}]}])

    # Block public rules, permitting only SSH: AWS's own default.
    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": True,
            "PermittedPublicSecurityGroupRuleRanges": [
                {"MinRange": _SSH_PORT, "MaxRange": _SSH_PORT}]})

    launch = dict(
        ReleaseLabel=RELEASE_LABEL,
        ServiceRole=service_role, JobFlowRole=job_flow_role,
        VisibleToAllUsers=True, Applications=[{"Name": "Hadoop"}], Tags=_TAGS,
        Instances={"InstanceCount": 1, "MasterInstanceType": INSTANCE_TYPE,
                   "KeepJobFlowAliveWhenNoSteps": True, "TerminationProtected": False,
                   "Ec2SubnetId": subnet,
                   "AdditionalMasterSecurityGroups": [open_sg]},
    )

    # RunJobFlow itself succeeds; the refusal arrives asynchronously as the cluster's terminal
    # StateChangeReason.
    refused_name = ctx.unique_name("sim2real-behav-emr-bpa-refused-")
    refused_id = _run_cluster(emr, ctx, Name=refused_name, **launch)

    def _refused():
        return emr.describe_cluster(ClusterId=refused_id)["Cluster"]

    state = _poll(ctx, lambda: _refused()["Status"]["State"], lambda s: s in _CLUSTER_SETTLED,
                  timeout_s=900, interval_s=2,
                  description=f"cluster {refused_id} settling after the blocked launch")
    cluster = _refused()
    assert state == "TERMINATED_WITH_ERRORS", (
        f"a cluster whose security group is open on a non-permitted port must be refused, landing "
        f"in TERMINATED_WITH_ERRORS; got {state!r} (reason "
        f"{cluster['Status'].get('StateChangeReason')!r})"
    )
    reason = cluster["Status"].get("StateChangeReason") or {}
    assert reason.get("Code") == "VALIDATION_ERROR", (
        f"the refusal must be reported as VALIDATION_ERROR, got {reason!r}"
    )
    message = reason.get("Message") or ""
    assert open_sg in message and str(_SSH_PORT) in message, (
        f"the refusal must name the offending security group and the permitted range so a caller "
        f"can act on it; group {open_sg!r}, permitted {_SSH_PORT!r}, message {message!r}"
    )

    # EMR refused before provisioning any EC2 capacity.
    refused_instances = _instances(emr, refused_id)
    assert refused_instances == [], (
        f"a refused launch must provision no EC2 instances at all; ListInstances on {refused_id} "
        f"returned {[(i['Ec2InstanceId'], i['Status']['State']) for i in refused_instances]!r}"
    )
    assert "ReadyDateTime" not in (cluster["Status"].get("Timeline") or {}), (
        f"a refused cluster must never become ready; its timeline was "
        f"{cluster['Status'].get('Timeline')!r}"
    )
    # The rejected launch did not mutate the account setting.
    still = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    assert still.get("BlockPublicSecurityGroupRules") is True, (
        f"the refused RunJobFlow must not have changed the account configuration; got {still!r}"
    )
    assert still.get("PermittedPublicSecurityGroupRuleRanges") == [
        {"MinRange": _SSH_PORT, "MaxRange": _SSH_PORT}], (
        f"the permitted-range list must be exactly what was configured; got {still!r}"
    )

    # Positive control: the only change is 1234 joining the exception list.
    emr.put_block_public_access_configuration(
        BlockPublicAccessConfiguration={
            "BlockPublicSecurityGroupRules": True,
            "PermittedPublicSecurityGroupRuleRanges": [
                {"MinRange": _SSH_PORT, "MaxRange": _SSH_PORT},
                {"MinRange": _OPEN_PORT, "MaxRange": _OPEN_PORT}]})

    allowed_name = ctx.unique_name("sim2real-behav-emr-bpa-allowed-")
    allowed_id = _run_cluster(emr, ctx, Name=allowed_name, **launch)

    def _allowed():
        return emr.describe_cluster(ClusterId=allowed_id)["Cluster"]

    # Instances appearing proves validation passed, without waiting out the whole boot.
    got = _poll(ctx, lambda: (_allowed()["Status"]["State"], len(_instances(emr, allowed_id))),
                lambda si: si[1] > 0 or si[0] in ("TERMINATED", "TERMINATED_WITH_ERRORS"),
                timeout_s=900, interval_s=2,
                description=f"cluster {allowed_id} provisioning instances once 1234 is permitted")
    allowed_state, n_instances = got
    assert allowed_state != "TERMINATED_WITH_ERRORS", (
        f"with {_OPEN_PORT} in the exception list the identical launch must not be refused; the "
        f"control cluster ended {allowed_state!r} "
        f"(reason {_allowed()['Status'].get('StateChangeReason')!r})"
    )
    assert n_instances > 0, (
        f"the control cluster must really provision EC2 capacity, proving the refusal above came "
        f"from the exception list and not from the request; ListInstances reported "
        f"{n_instances} instances in state {allowed_state!r}"
    )


def _delete_emr_default_security_groups(ctx, timeout_s=240.0, interval_s=2.0):
    """Delete the ElasticMapReduce-* groups EMR creates in the run's shared network.

    EMR mints these default groups on its first launch in a VPC and never deletes them, so left
    behind they keep the shared network from being deleted. They reference each other, so their
    rules are revoked first; a group still held by a terminating cluster's ENIs is retried.
    """
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    vpc_id = ctx.network().vpc_id
    deadline = time.monotonic() + timeout_s
    while True:
        groups = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["ElasticMapReduce-*"]},
            ]
        )["SecurityGroups"]
        if not groups:
            return
        for group in groups:
            for key, revoke in (
                ("IpPermissions", ec2.revoke_security_group_ingress),
                ("IpPermissionsEgress", ec2.revoke_security_group_egress),
            ):
                refs = [perm for perm in group.get(key, []) if perm.get("UserIdGroupPairs")]
                if refs:
                    try:
                        revoke(GroupId=group["GroupId"], IpPermissions=refs)
                    except ClientError as e:
                        if e.response["Error"]["Code"] not in (
                            "InvalidGroup.NotFound", "InvalidPermission.NotFound"
                        ):
                            raise
        pending = []
        for group in groups:
            try:
                ec2.delete_security_group(GroupId=group["GroupId"])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "DependencyViolation":
                    pending.append(f"{group['GroupId']}: {code}")
                elif code != "InvalidGroup.NotFound":
                    raise
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"EMR default security groups still in {vpc_id}: {pending}")
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
