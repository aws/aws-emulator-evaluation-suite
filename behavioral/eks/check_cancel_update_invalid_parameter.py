"""cancel-update-invalid-parameter."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn; return (Code, Message). An unexpected SUCCESS raises, because an emulator ACCEPTING
    input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to fail, but it succeeded and returned {result!r}")

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
    ctx.on_cleanup(lambda: c.deregister_cluster(name=name))
    return resp["cluster"], role_arn

CHECK = "cancel-update-invalid-parameter"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelUpdate fails with ResourceNotFoundException naming an unknown cluster, and with ClientException
    "This operation is not supported for connected clusters" for a malformed update id on a connected
    cluster.
    """
    c = ctx.client("eks")
    if not hasattr(c, "cancel_update"):
        raise AssertionError(
            "EKS CancelUpdate is unavailable in this botocore/endpoint "
            "(client has no attribute 'cancel_update')"
        )
    missing = ctx.unique_name("sim2real-behav-no-cluster-")
    bogus = _expect_error(lambda: c.cancel_update(name=missing, updateId=str(uuid.uuid4())))
    assert bogus == (
        "ResourceNotFoundException",
        f"No cluster found for name: {missing}.",
    ), f"expected ResourceNotFoundException, got {bogus!r}"

    cluster, _ = _register_connected_cluster(ctx)
    code = _expect_error(
        lambda: c.cancel_update(name=cluster["name"], updateId="not-a-valid-update-id")
    )
    assert code == (
        "ClientException",
        "This operation is not supported for connected clusters",
    ), (
        f"expected ClientException for a malformed updateId on an existing cluster, got {code!r} "
        f"(unknown-cluster case returned {bogus!r})"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
