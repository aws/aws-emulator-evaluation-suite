"""op-register-cluster-validation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SSM_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _delete_role(iam, name):
    try:
        iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _connector_role(ctx):
    """Create-or-adopt an IAM role that is a valid EKS Connector roleArn."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-eks-connector-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    })
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=trust,
            Description="SimParityCorpus EKS behavioral fidelity fixture",
            Tags=[{"Key": "sim2real", "Value": "1"}],
        )["Role"]["Arn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        else:
            raise
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_POLICY)
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return arn


def _retry_on(fn, codes, timeout_s=420, interval_s=20):
    """Call fn, retrying while it fails with one of *codes* (genuinely-eventual EKS behavior)."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in codes or time.time() >= deadline:
                raise
            time.sleep(interval_s)

CHECK = "op-register-cluster-validation"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] RegisterCluster MUST reject a malformed connector role ARN with InvalidParameterException, and must not leave a connected cluster behind."""
    c = ctx.client("eks")

    # Positive control: a syntactically-valid RegisterCluster must succeed, so the
    # rejection below is provably about the malformed ARN, not about every RegisterCluster.
    role_arn = _connector_role(ctx)
    good_name = ctx.unique_name("sim2real-behav-eks-conn-ok-")
    registered = _retry_on(
        lambda: c.register_cluster(
            name=good_name,
            connectorConfig={"roleArn": role_arn, "provider": "OTHER"},
            tags={"sim2real": "1"},
        ),
        # A freshly created role reads as "Nonexistent role" (InvalidRequestException) until IAM propagates it.
        {"ResourcePropagationDelayException", "InvalidRequestException"},
    )["cluster"]
    ctx.on_cleanup(lambda: c.deregister_cluster(name=good_name))
    assert registered["status"] in ("PENDING", "CREATING"), registered

    name = ctx.unique_name("sim2real-behav-eks-conn-")

    code, msg = _expect_error(
        lambda: c.register_cluster(
            name=name,
            connectorConfig={"roleArn": "not-an-arn", "provider": "OTHER"},
        )
    )
    assert code == "InvalidParameterException", f"bad connector role -> {code}: {msg}"
    assert msg == "The provided roleArn is invalid.", f"bad connector role -> {code}: {msg}"

    # The rejected registration must not have created anything.
    code, msg = _expect_error(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", (
        f"a rejected RegisterCluster still materialised {name}: {code}"
    )
    assert msg == f"No cluster found for name: {name}.", msg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
