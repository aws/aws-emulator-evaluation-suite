"""capability-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn, require it raises ClientError, return its (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _succeeds(fn):
    """Call fn; True when it succeeds, False while it is refused with AccessDeniedException."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
            raise
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

def _restricted_client(ctx):
    """An eks client for a principal granted exactly eks:ListClusters.

    Emulators routinely ignore authorization entirely; that is the fidelity gap
    this check measures, so the call is made against whatever target is under
    test from a principal that genuinely lacks the action. Returns
    (eks_client, role_arn).
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
    # The one grant we DID make must work, or a later AccessDenied would be
    # ambiguous (bad creds vs. genuine authorization failure).
    _wait_for(
        lambda: _succeeds(lambda: client.list_clusters(maxResults=1)),
        lambda ok: ok,
        timeout_s=120,
        interval_s=5,
        desc="low-privilege role can call its one allowed action",
    )
    return client, role_arn

CHECK = "capability-access-denied"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role granted only eks:ListClusters gets AccessDeniedException with the exact IAM message on
    Create/Describe/Delete/ListCapabilities, while an admin caller gets ResourceNotFoundException on the
    same calls and the role's ListClusters succeeds.
    """
    if not hasattr(ctx.client("eks"), "create_capability"):
        raise AssertionError("botocore build does not model eks capability APIs")

    admin = ctx.client("eks")
    cluster = ctx.unique_name("sim2real-behav-cap-cl-")
    capability = ctx.unique_name("sim2real-behav-cap-")

    client, role_arn = _restricted_client(ctx)

    baseline = {
        "delete": _error(
            lambda: admin.delete_capability(clusterName=cluster, capabilityName=capability)
        ),
        "create": _error(
            lambda: admin.create_capability(
                capabilityName=capability,
                clusterName=cluster,
                type="ARGOCD",
                roleArn=role_arn,
                deletePropagationPolicy="RETAIN",
            )
        ),
        "describe": _error(
            lambda: admin.describe_capability(clusterName=cluster, capabilityName=capability)
        ),
        "list": _error(lambda: admin.list_capabilities(clusterName=cluster)),
    }
    # An absent capability on an absent cluster reports the resource; an absent cluster
    # alone reports the cluster by name.
    missing_resource = "The requested resource does not exist."
    missing_cluster = f"No cluster found for name: {cluster}."
    expected_baseline = {
        "delete": ("ResourceNotFoundException", missing_resource),
        "create": ("ResourceNotFoundException", missing_cluster),
        "describe": ("ResourceNotFoundException", missing_resource),
        "list": ("ResourceNotFoundException", missing_cluster),
    }
    assert baseline == expected_baseline, baseline

    codes = {
        "delete": _error(
            lambda: client.delete_capability(clusterName=cluster, capabilityName=capability)
        ),
        "create": _error(
            lambda: client.create_capability(
                capabilityName=capability,
                clusterName=cluster,
                type="ARGOCD",
                roleArn=role_arn,
                deletePropagationPolicy="RETAIN",
            )
        ),
        "describe": _error(
            lambda: client.describe_capability(clusterName=cluster, capabilityName=capability)
        ),
        "list": _error(lambda: client.list_capabilities(clusterName=cluster)),
    }
    account = role_arn.split(":")[4]
    principal = f"arn:aws:sts::{account}:assumed-role/{role_arn.rsplit('/', 1)[1]}/sim2real-behav"
    cluster_arn = f"arn:aws:eks:{ctx.region}:{account}:cluster/{cluster}"
    capability_arn = f"arn:aws:eks:{ctx.region}:{account}:capability/{cluster}/{capability}/*"

    def denied(action, resource):
        return (
            "AccessDeniedException",
            f"User: {principal} is not authorized to perform: eks:{action} on resource: "
            f"{resource} because no identity-based policy allows the eks:{action} action",
        )

    expected_codes = {
        "delete": denied("DeleteCapability", capability_arn),
        "create": denied("CreateCapability", cluster_arn),
        "describe": denied("DescribeCapability", capability_arn),
        "list": denied("ListCapabilities", cluster_arn),
    }
    assert codes == expected_codes, codes
    # Control: the one action the role IS granted still works, proving the denials
    # above are authorization decisions rather than broken credentials.
    assert client.list_clusters(maxResults=1) is not None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
