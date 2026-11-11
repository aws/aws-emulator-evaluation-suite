"""register-cluster-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _succeeds(fn):
    """Call fn; True when it returns, False when it raises a ClientError."""
    try:
        fn()
    except ClientError:
        return False
    return True

def _wait_for(fn, pred, timeout_s=180, interval_s=5, desc=""):
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

def _deregister_if_present(eks, name):
    """Teardown: deregister the connected cluster unless the check already removed it."""
    try:
        eks.deregister_cluster(name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _connector_role(ctx, iam):
    """A throwaway role trusted by ssm.amazonaws.com.

    RegisterCluster validates connectorConfig.roleArn against the EKS Connector
    agent's SSM hybrid-activation trust requirement, not against the caller's own
    identity -- a role merely assumable by the account root (the low-privilege
    principal's own role) fails that validation regardless of authorization.
    """
    name = ctx.unique_name("sim2real-behav-connector-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ssm.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real behavioral fidelity: EKS Connector role",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    )
    return role_arn

def _restricted_client(ctx):
    """An eks client for a principal granted exactly eks:ListClusters.

    Emulators routinely ignore authorization entirely, so the only way to pin
    real EKS's AccessDeniedException semantics is to call from a principal that
    genuinely lacks the action. Returns (eks_client, account, iam_client, role_name)
    so the caller can later widen the role's policy for the restore beat.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-lowpriv-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real behavioral fidelity: intentionally list-only",
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    role_arn = f"arn:aws:iam::{account}:role/{name}"
    iam.put_role_policy(
        RoleName=name,
        PolicyName="eks-list-only",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["eks:ListClusters"], "Resource": "*"}
                ],
            }
        ),
    )

    def try_assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")
        except ClientError:
            return None

    creds = _wait_for(
        try_assume,
        lambda r: r is not None,
        timeout_s=180,
        interval_s=5,
        desc="assume low-privilege role (IAM propagation)",
    )["Credentials"]
    # Re-signed through ctx.client(creds=...) so the second hop keeps THIS target's
    # endpoint -- a hand-rolled boto3.client() here would reach real AWS on an
    # emulator run and the check would grade the wrong target.
    client = ctx.client(
        "eks",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    _wait_for(
        lambda: _succeeds(lambda: client.list_clusters(maxResults=1)),
        lambda ok: ok,
        timeout_s=120,
        interval_s=5,
        desc="low-privilege role can call its one allowed action",
    )
    return client, account, iam, name

CHECK = "register-cluster-access-denied"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterCluster and DeregisterCluster without permission fail with AccessDeniedException and the exact
    IAM message, and no cluster is registered; once the same principal is granted them, the identical calls
    succeed and the cluster is gone, so a target that denies unconditionally fails."""
    client, account, iam, role_name = _restricted_client(ctx)
    connector_role_arn = _connector_role(ctx, iam)
    name = ctx.unique_name("sim2real-behav-reg-")
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/sim2real-behav"
    cluster_arn = f"arn:aws:eks:{ctx.region}:{account}:cluster/{name}"
    for op, call in (
        (
            "RegisterCluster",
            lambda: client.register_cluster(
                name=name,
                connectorConfig={"roleArn": connector_role_arn, "provider": "OTHER"},
            ),
        ),
        ("DeregisterCluster", lambda: client.deregister_cluster(name=name)),
    ):
        code, msg = _expect_error(call)
        assert code == "AccessDeniedException", f"{op} without permission -> {code}: {msg}"
        assert msg == (
            f"User: {caller} is not authorized to perform: eks:{op} on resource: {cluster_arn} "
            f"because no identity-based policy allows the eks:{op} action"
        ), f"{op} without permission -> {msg!r}"

    # The denied RegisterCluster must not have created the cluster: an authorized
    # caller still sees nothing under that name.
    admin = ctx.client("eks")
    absent_code, absent_msg = _expect_error(lambda: admin.deregister_cluster(name=name))
    assert absent_code == "ResourceNotFoundException", (
        f"denied RegisterCluster left a trace: expected ResourceNotFoundException, got {absent_code!r}"
    )
    assert absent_msg == f"No cluster found for name: {name}.", f"deregister after denial -> {absent_msg!r}"

    # Restore: grant what the documented RegisterCluster policy requires (the two actions,
    # iam:PassRole on the connector role, and creating the EKS Connector service-linked role when
    # it does not exist yet), then demand the identical calls succeed.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="eks-register-deregister",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["eks:RegisterCluster", "eks:DeregisterCluster"],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": connector_role_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": "iam:CreateServiceLinkedRole",
                        "Resource": (
                            "arn:aws:iam::*:role/aws-service-role/"
                            "eks-connector.amazonaws.com/AWSServiceRoleForAmazonEKSConnector"
                        ),
                        "Condition": {
                            "StringEquals": {"iam:AWSServiceName": "eks-connector.amazonaws.com"}
                        },
                    },
                ],
            }
        ),
    )

    def _try_register():
        try:
            return ("ok", client.register_cluster(
                name=name,
                connectorConfig={"roleArn": connector_role_arn, "provider": "OTHER"},
            )["cluster"])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return ("error", err.get("Code"), err.get("Message"))

    def _still_propagating(o):
        if o[0] == "ok":
            return False
        code = o[1]
        if code in ("AccessDeniedException", "ResourcePropagationDelayException"):
            return True
        # The service-linked role EKS Connector needs is created lazily on first
        # use; the grant that lets US create it can itself take a few seconds to
        # propagate, during which real AWS reports the SLR as merely unavailable.
        if code == "InvalidRequestException" and "AWSServiceRoleForAmazonEKSConnector" in (o[2] or ""):
            return True
        return False

    outcome = _wait_for(
        _try_register,
        lambda o: not _still_propagating(o),
        timeout_s=180,
        interval_s=5,
        desc="grant propagates and the identical RegisterCluster call succeeds",
    )
    kind = outcome[0]
    assert kind == "ok", f"RegisterCluster still failing after granting the permission: {outcome[1:]}"
    registered = outcome[1]
    assert registered["name"] == name, registered
    ctx.on_cleanup(lambda: _deregister_if_present(admin, name))

    described = admin.describe_cluster(name=name)["cluster"]
    assert described["name"] == name, described

    def _try_deregister():
        try:
            return ("ok", client.deregister_cluster(name=name)["cluster"])
        except ClientError as exc:
            return ("error", exc.response.get("Error", {}).get("Code"))

    # The SAME grant that just let RegisterCluster through can still lag for
    # DeregisterCluster -- IAM's eventual-consistency window is per-call, not
    # per-policy, so a transient AccessDeniedException here is propagation, not
    # a genuine gap in the policy just written.
    outcome = _wait_for(
        _try_deregister,
        lambda o: o[0] == "ok" or o[1] != "AccessDeniedException",
        timeout_s=60,
        interval_s=5,
        desc="grant propagates to DeregisterCluster",
    )
    assert outcome[0] == "ok", f"DeregisterCluster still failing after granting the permission: {outcome[1:]}"
    assert outcome[1]["name"] == name, outcome[1]
    assert outcome[1]["status"] == "DELETING", outcome[1]

    def _describe_state():
        try:
            return ("present", admin.describe_cluster(name=name)["cluster"]["status"])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return ("error", err.get("Code"), err.get("Message"))

    gone = _wait_for(
        _describe_state,
        lambda o: o[0] == "error",
        timeout_s=180,
        interval_s=5,
        desc=f"registered cluster {name} torn down",
    )
    assert gone[1] == "ResourceNotFoundException", f"describe after deregister -> {gone[1:]}"
    assert gone[2] == f"No cluster found for name: {name}.", f"describe after deregister -> {gone[2]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
