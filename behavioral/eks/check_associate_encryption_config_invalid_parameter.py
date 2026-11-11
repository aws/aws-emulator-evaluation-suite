"""associate-encryption-config-invalid-parameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")

def _wait_for(fn, pred, timeout_s=240, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)

def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=pol)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _create_connector_role(ctx):
    """Create an IAM role the EKS connector service can assume; return its ARN."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-connector-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["eks-connector.amazonaws.com", "ssm.amazonaws.com"]
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real behavioral fidelity: EKS connector role",
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonEKSConnectorAgentPolicy",
        )
    except ClientError:
        pass
    return f"arn:aws:iam::{account}:role/{role_name}"

def _register_connected_cluster(ctx, provider="OTHER", timeout_s=240):
    """RegisterCluster with a fresh connector role, tolerating IAM propagation.

    Registration of a connected cluster is control-plane-only (no EC2/VPC
    provisioning) so it completes in seconds. Returns (cluster_dict, role_arn).
    """
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-connected-")
    role_arn = _create_connector_role(ctx)

    def attempt():
        try:
            return c.register_cluster(
                name=name, connectorConfig={"roleArn": role_arn, "provider": provider}
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (
                "ResourcePropagationDelayException",
                "InvalidRequestException",
                "InvalidParameterException",
                "AccessDeniedException",
            ):
                return None
            raise

    resp = _wait_for(
        attempt,
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=5,
        desc="RegisterCluster accepted (connector role propagation)",
    )
    ctx.on_cleanup(lambda: c.deregister_cluster(name=name))
    return resp["cluster"], role_arn

CHECK = "associate-encryption-config-invalid-parameter"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateEncryptionConfig on a nonexistent cluster is ResourceNotFoundException; on a connected
    cluster a malformed and a valid KMS key ARN both hit the same connected-cluster ClientException,
    and neither leaves an encryptionConfig on the cluster.
    """
    c = ctx.client("eks")
    missing = ctx.unique_name("sim2real-behav-no-cluster-")
    bogus_code, bogus_msg = _expect_error(
        lambda: c.associate_encryption_config(
            clusterName=missing,
            encryptionConfig=[
                {"resources": ["secrets"], "provider": {"keyArn": "not-a-kms-key-arn"}}
            ],
        )
    )
    assert bogus_code == "ResourceNotFoundException", f"{bogus_code}: {bogus_msg}"
    assert bogus_msg == f"No cluster found for name: {missing}.", bogus_msg

    cluster, _ = _register_connected_cluster(ctx)
    name = cluster["name"]

    # A connected cluster has no reachable keyArn-shape check; the gate fires first.
    _GATE = ("ClientException", "This operation is not supported for connected clusters")

    bad = _expect_error(
        lambda: c.associate_encryption_config(
            clusterName=name,
            encryptionConfig=[
                {"resources": ["secrets"], "provider": {"keyArn": "not-a-kms-key-arn"}}
            ],
        )
    )
    assert bad == _GATE, (
        f"malformed keyArn on connected cluster {name} -> {bad}; expected the "
        f"connected-cluster gate {_GATE}"
    )

    kms = ctx.client("kms")
    real_key_arn = kms.create_key(Description=ctx.unique_name("sim2real-behav-probe-"))[
        "KeyMetadata"
    ]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=real_key_arn, PendingWindowInDays=7))

    good = _expect_error(
        lambda: c.associate_encryption_config(
            clusterName=name,
            encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": real_key_arn}}],
        )
    )
    assert good == _GATE, (
        f"a syntactically VALID KMS key ARN on connected cluster {name} -> {good}; expected "
        f"the same connected-cluster gate {_GATE} as the malformed keyArn got ({bad}). If "
        f"these ever differ, the refusal is genuinely about keyArn validity and this check's "
        f"premise (the connected-cluster gate, not parameter validation) no longer holds."
    )

    # ListUpdates is refused by the same connected-cluster gate, so DescribeCluster is the read.
    after = c.describe_cluster(name=name)["cluster"]
    assert not after.get("encryptionConfig"), (
        f"connected cluster {name} carries an encryptionConfig after two refused "
        f"associations: {after.get('encryptionConfig')!r}"
    )
    assert after["name"] == name and after.get("connectorConfig"), (
        f"connected cluster {name} lost its connectorConfig after two refused "
        f"associations: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
