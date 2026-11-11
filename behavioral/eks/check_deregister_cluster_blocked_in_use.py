"""deregister-cluster-blocked-in-use."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _cluster_gone(c, name):
    """True once DescribeCluster reports the cluster as not found."""
    try:
        c.describe_cluster(name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False

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
        Tags=[{"Key": "sim2real", "Value": "1"}],
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
                name=name,
                connectorConfig={"roleArn": role_arn, "provider": provider},
                tags={"sim2real": "1"},
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
    ctx.on_cleanup(lambda: _deregister_if_present(c, name))
    return resp["cluster"], role_arn


def _deregister_if_present(c, name):
    """Teardown: the check itself deregisters the cluster, so absence is the clean outcome."""
    try:
        c.deregister_cluster(name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

CHECK = "deregister-cluster-blocked-in-use"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a connected cluster exists, RegisterCluster on its name fails with ResourceInUseException and its
    exact message; DeregisterCluster succeeds, and repeating it fails with ResourceNotFoundException "No
    cluster found for name: <name>.".
    """
    c = ctx.client("eks")
    cluster, role_arn = _register_connected_cluster(ctx)
    name = cluster["name"]

    in_use, in_use_message = _error(
        lambda: c.register_cluster(
            name=name, connectorConfig={"roleArn": role_arn, "provider": "OTHER"}
        )
    )
    assert in_use == "ResourceInUseException", (
        f"expected the registered name to be in use, got {in_use} "
        f"(register_status={cluster.get('status')})"
    )
    assert in_use_message == f"Cluster already exists with name: {name}", repr(in_use_message)

    resp = c.deregister_cluster(name=name)
    assert resp["cluster"]["name"] == name, resp["cluster"]
    assert resp["cluster"]["status"] in ("DELETING", "PENDING", "ACTIVE", "CREATING"), resp[
        "cluster"
    ]["status"]

    _wait_for(
        lambda: _cluster_gone(c, name),
        lambda gone: gone,
        timeout_s=180,
        interval_s=3,
        desc="connected cluster fully deregistered",
    )
    repeat, repeat_message = _error(lambda: c.deregister_cluster(name=name))
    assert repeat == "ResourceNotFoundException", repeat
    assert repeat_message == f"No cluster found for name: {name}.", repr(repeat_message)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
