"""associate-identity-provider-config-invalid-parameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                tags={"sim2real": CHECK},
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

CHECK = "associate-identity-provider-config-invalid-parameter"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateIdentityProviderConfig fails with ResourceNotFoundException on an unknown cluster, and with
    the same connected-cluster ClientException for a malformed and a well-formed issuer on a connected
    cluster.
    """
    c = ctx.client("eks")
    missing = ctx.unique_name("sim2real-behav-no-cluster-")
    bogus = _expect_error(
        lambda: c.associate_identity_provider_config(
            clusterName=missing,
            oidc={
                "identityProviderConfigName": ctx.unique_name("sim2real-behav-idp-"),
                "issuerUrl": "http://not-https.example.com/oidc",
                "clientId": "sim2real-behav-client",
            },
        )
    )
    assert bogus == ("ResourceNotFoundException", f"No cluster found for name: {missing}."), bogus

    _GATE = ("ClientException", "This operation is not supported for connected clusters")
    cluster, _ = _register_connected_cluster(ctx)
    malformed_code = _expect_error(
        lambda: c.associate_identity_provider_config(
            clusterName=cluster["name"],
            oidc={
                "identityProviderConfigName": ctx.unique_name("sim2real-behav-idp-"),
                "issuerUrl": "http://not-https.example.com/oidc",
                "clientId": "sim2real-behav-client",
            },
        )
    )
    assert malformed_code == _GATE, (
        f"existing connected cluster, malformed issuer -> {malformed_code} (bogus -> {bogus})"
    )

    # Positive control: the SAME connected cluster, a well-formed https issuer. If this also
    # comes back ClientException, the gate fires ahead of OIDC payload validation for this op --
    # proving the refusal above is the connected-cluster gate, not evidence that the malformed
    # issuer was specifically detected.
    wellformed_code = _expect_error(
        lambda: c.associate_identity_provider_config(
            clusterName=cluster["name"],
            oidc={
                "identityProviderConfigName": ctx.unique_name("sim2real-behav-idp-"),
                "issuerUrl": "https://sim2real-behav.example.com/oidc",
                "clientId": "sim2real-behav-client",
            },
        )
    )
    assert wellformed_code == _GATE, (
        f"existing connected cluster, well-formed issuer -> {wellformed_code} "
        f"(malformed -> {malformed_code}); expected the identical connected-cluster gate"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
