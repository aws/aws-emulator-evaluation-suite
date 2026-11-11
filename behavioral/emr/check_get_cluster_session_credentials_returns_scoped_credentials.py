"""get-cluster-session-credentials-returns-scoped-credentials."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "get-cluster-session-credentials-returns-scoped-credentials"
GROUP = "data-plane"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetClusterSessionCredentials on an FGAC cluster returns distinct usernames for two runtime
    roles, the same username when a role is re-requested, and non-empty passwords.
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    cluster_id, ec2_role_name = _launch_fgac_cluster(ctx)
    iam = ctx.client("iam")
    ec2_role_arn = iam.get_role(RoleName=ec2_role_name)["Role"]["Arn"]

    role_a_arn, _ = _ensure_runtime_role(ctx, ec2_role_arn, "a")
    role_b_arn, _ = _ensure_runtime_role(ctx, ec2_role_arn, "b")

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:TagSession"],
                "Resource": [role_a_arn, role_b_arn],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=ec2_role_name, PolicyName="AllowRuntimeRoleUsage", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=ec2_role_name, PolicyName="AllowRuntimeRoleUsage"))

    emr = ctx.client("emr")
    resp_a = _get_creds_with_retry(emr, cluster_id, role_a_arn)
    resp_b = _get_creds_with_retry(emr, cluster_id, role_b_arn)
    resp_a_again = _get_creds_with_retry(emr, cluster_id, role_a_arn)

    user_a = resp_a["Credentials"]["UsernamePassword"]["Username"]
    user_b = resp_b["Credentials"]["UsernamePassword"]["Username"]
    user_a_again = resp_a_again["Credentials"]["UsernamePassword"]["Username"]
    assert user_a and user_b, f"expected non-empty usernames for both roles, got {user_a!r} and {user_b!r}"
    assert user_a != user_b, f"credentials for two different execution roles must not be identical, both were {user_a!r}"
    assert user_a_again == user_a, (
        f"re-requesting credentials for the same execution role {role_a_arn} must return the same scoped "
        f"username, got {user_a!r} then {user_a_again!r}"
    )
    assert resp_a["Credentials"]["UsernamePassword"]["Password"], "expected a non-empty password for role a"
    assert resp_b["Credentials"]["UsernamePassword"]["Password"], "expected a non-empty password for role b"


_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"


def _trust_policy(service):
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    )


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


def _ensure_emr_roles(ctx):
    iam = ctx.client("iam")
    svc_name = ctx.unique_name("sim2real-emrsvc-")
    ec2_name = ctx.unique_name("sim2real-emrec2-")

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=_trust_policy("elasticmapreduce.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    iam.attach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=_trust_policy("ec2.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY))
    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))
    return svc_name, ec2_name


def _create_security_configuration_fgac(ctx):
    emr = ctx.client("emr")
    name = ctx.unique_name("sim2real-emr-secconf-")
    tls_s3_uri = _upload_tls_cert_bundle(ctx)
    config = {
        "AuthorizationConfiguration": {"IAMConfiguration": {"EnableApplicationScopedIAMRole": True}},
        # GetClusterSessionCredentials raises InvalidRequestException unless in-transit
        # encryption is enabled too, hence the self-signed PEM bundle.
        "EncryptionConfiguration": {
            "EnableInTransitEncryption": True,
            "EnableAtRestEncryption": False,
            "InTransitEncryptionConfiguration": {
                "TLSCertificateConfiguration": {
                    "CertificateProviderType": "PEM",
                    "S3Object": tls_s3_uri,
                }
            },
        },
    }
    emr.create_security_configuration(Name=name, SecurityConfiguration=json.dumps(config))
    ctx.on_cleanup(lambda: _retry_while_held(lambda: emr.delete_security_configuration(Name=name), "InvalidRequestException", timeout_s=840.0))
    return name


def _run_openssl(args):
    import subprocess

    result = subprocess.run(["openssl", *args], capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed: {result.stderr.decode(errors='replace')}")


def _generate_tls_cert_bundle():
    """A self-signed CA plus a leaf cert/key signed by it, in the three-file layout
    GetClusterSessionCredentials' TLS PEM provider requires: privateKey.pem (the leaf key),
    certificateChain.pem (leaf + CA), trustedCertificates.pem (the CA, trusted by every node)."""
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        ca_key, ca_crt = os.path.join(d, "ca.key"), os.path.join(d, "ca.crt")
        leaf_key, leaf_csr, leaf_crt = (os.path.join(d, n) for n in ("leaf.key", "leaf.csr", "leaf.crt"))
        _run_openssl(["genrsa", "-out", ca_key, "2048"])
        _run_openssl(
            ["req", "-x509", "-new", "-nodes", "-key", ca_key, "-sha256", "-days", "2",
             "-subj", "/CN=sim2real-emr-fgac-ca", "-out", ca_crt]
        )
        _run_openssl(["genrsa", "-out", leaf_key, "2048"])
        _run_openssl(["req", "-new", "-key", leaf_key, "-subj", "/CN=sim2real-emr-fgac-node", "-out", leaf_csr])
        _run_openssl(
            ["x509", "-req", "-in", leaf_csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
             "-out", leaf_crt, "-days", "2", "-sha256"]
        )
        with open(leaf_crt, "rb") as f:
            leaf_pem = f.read()
        with open(leaf_key, "rb") as f:
            leaf_key_pem = f.read()
        with open(ca_crt, "rb") as f:
            ca_pem = f.read()
    return leaf_key_pem, leaf_pem + ca_pem, ca_pem


def _upload_tls_cert_bundle(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-tls-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))

    private_key_pem, chain_pem, trusted_pem = _generate_tls_cert_bundle()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("privateKey.pem", private_key_pem)
        zf.writestr("certificateChain.pem", chain_pem)
        zf.writestr("trustedCertificates.pem", trusted_pem)
    key = "tls-certs.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return f"s3://{bucket}/{key}"


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _ensure_runtime_role(ctx, ec2_role_arn, suffix):
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-emrrt-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAssumeRole",
                "Effect": "Allow",
                "Principal": {"AWS": ec2_role_arn},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Arn"], name


def _run_job_flow_with_retry(emr, timeout_s=120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            if "role" in msg or "profile" in msg or "not authorized" in msg:
                last_err = exc
                time.sleep(2)
                continue
            raise
    raise last_err


def _cleanup_cluster(ctx, cluster_id):
    emr = ctx.client("emr")
    ctx.on_cleanup(lambda: _terminate_and_wait(emr, cluster_id))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_cluster_running(ctx, cluster_id):
    emr = ctx.client("emr")
    timeout_s = _budget_s(ctx, 1200.0)
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in ("RUNNING", "WAITING"):
            return
        if state in ("TERMINATING", "TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster {cluster_id} reached {state} before RUNNING/WAITING")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} reaching RUNNING/WAITING: the run budget ended first; not graded")
    raise AssertionError(f"cluster {cluster_id} not RUNNING/WAITING within {timeout_s:.0f}s (last {state})")


def _launch_fgac_cluster(ctx):
    subnet_id = _default_subnet(ctx)
    master_sg, slave_sg = _own_emr_security_groups(ctx)
    svc_role, ec2_role = _ensure_emr_roles(ctx)
    sec_config = _create_security_configuration_fgac(ctx)
    emr = ctx.client("emr")
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-fgac-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances={
            "InstanceGroups": [
                {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1, "Name": "master"},
                {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1, "Name": "core"},
            ],
            "Ec2SubnetId": subnet_id,
            "EmrManagedMasterSecurityGroup": master_sg,
            "EmrManagedSlaveSecurityGroup": slave_sg,
            "KeepJobFlowAliveWhenNoSteps": True,
        },
        ServiceRole=svc_role,
        JobFlowRole=ec2_role,
        SecurityConfiguration=sec_config,
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    cluster_id = resp["JobFlowId"]
    _cleanup_cluster(ctx, cluster_id)
    _wait_cluster_running(ctx, cluster_id)
    return cluster_id, ec2_role


def _get_creds_with_retry(emr, cluster_id, role_arn, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.get_cluster_session_credentials(ClusterId=cluster_id, ExecutionRoleArn=role_arn)
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(2)
    raise last_err


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=2.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


def _own_emr_security_groups(ctx):
    """Two new security groups for the EMR-managed primary and core security groups.

    EMR adds its rules here instead of the shared VPC-wide ElasticMapReduce-* default groups.
    """
    ec2 = ctx.client("ec2")
    group_ids = []
    ctx.on_cleanup(lambda: _delete_emr_security_groups(ec2, group_ids))
    for role in ("master", "slave"):
        group_ids.append(ec2.create_security_group(
            GroupName=ctx.unique_name(f"sim2real-emr-{role}-"),
            Description=f"sim2real EMR-managed {role} security group",
            VpcId=ctx.network().vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
        )["GroupId"])
    return group_ids[0], group_ids[1]


def _delete_emr_security_groups(ec2, group_ids, timeout_s=600.0, interval_s=2.0):
    """Revoke the rules EMR added between the two groups, then delete both; a group still held by
    the terminating cluster's network interfaces is retried until the deadline, then raised."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    remaining = list(group_ids)
    while remaining:
        try:
            groups = ec2.describe_security_groups(GroupIds=remaining)["SecurityGroups"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidGroup.NotFound":
                raise
            groups = [
                g for gid in remaining
                for g in _describe_group_or_none(ec2, gid)
            ]
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
                        if e.response["Error"]["Code"] != "InvalidPermission.NotFound":
                            raise
        pending = []
        for group in groups:
            try:
                ec2.delete_security_group(GroupId=group["GroupId"])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    continue
                if code != "DependencyViolation":
                    raise
                pending.append(group["GroupId"])
        remaining = pending
        if remaining and time.monotonic() >= deadline:
            raise AssertionError(f"EMR security groups {remaining} still in use {timeout_s}s after teardown began")
        if remaining:
            time.sleep(interval_s)


def _describe_group_or_none(ec2, group_id):
    from botocore.exceptions import ClientError

    try:
        return ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            return []
        raise


def _terminate_and_wait(emr, cluster_id):
    """Terminate the cluster and wait until it is TERMINATED, so its instances' network interfaces
    leave its security groups before those are deleted."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    deadline = time.monotonic() + 800.0
    while emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"] not in (
        "TERMINATED", "TERMINATED_WITH_ERRORS"
    ):
        if time.monotonic() >= deadline:
            raise AssertionError(f"EMR cluster {cluster_id} not terminated 800s after TerminateJobFlows")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
