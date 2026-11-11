"""kubectl-denied-verb-returns-the-exact-forbidden-message-while-a-permitted-verb-succeeds."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kubectl-denied-verb-returns-the-exact-forbidden-message-while-a-permitted-verb-succeeds"
GROUP = "data-plane"
SERVICES = ["eks"]

_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
#: Zone IDs real AWS refuses for an EKS control plane.
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_FIXTURE_TAGS = {"sim2real": "eks-native-dp", "sim2real:managed": "true"}

_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_ROLE_PROPAGATION_TIMEOUT_S = 180

# Marks a failure in which the cluster's Kubernetes API did not do its part: kubectl fails in ITS
# OWN wording ("connection refused", "couldn't get current server API group list"), which
# otherwise reads like a local connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
#: The sibling marker for a control-plane state machine that accepted the create and never
#: converged, kept distinct so a query for one never silently returns the other.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


# ===== helpers =====


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{STATE_MARKER}: timed out after {timeout_s}s waiting for {desc}; last={val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole"],
                }
            ],
        }
    )


def _create_role(ctx, name, service, managed_policies):
    """Create the role this check needs and register its teardown before anything uses it."""
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(service),
        Description="sim2real eks native data-plane fidelity check",
        Tags=[{"Key": k, "Value": v} for k, v in sorted(_FIXTURE_TAGS.items())],
    )["Role"]["Arn"]

    def _drop_role():
        for policy_arn in managed_policies:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_drop_role)
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _call_tolerating_role_propagation(fn, desc):
    """Retry the EKS call that consumes a just-created role while IAM is still eventually
    consistent. EKS validates the role SYNCHRONOUSLY and rejects it with
    InvalidParameterException until the role is visible to it; retrying the dependent call
    (rather than sleeping a guessed interval) is what makes that correct."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterException" or "role" not in err.get(
                "Message", ""
            ).lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with InvalidParameterException on the role after "
                    f"{_ROLE_PROPAGATION_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _fixture_subnets(ctx):
    """Subnets in >=2 available AZs an EKS control plane accepts.

    The AZ set is derived from the account, never hardcoded: `describe_availability_zones`
    reports zone state, and some AZs EKS itself refuses. The account-level network subnets are
    used (and created, once, if the account has none) because an EKS control plane needs two
    zones and the default VPC quota is 5.
    """
    ec2 = ctx.client("ec2")
    usable = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneId"] not in _BAD_AZS
    }
    assert usable, f"no available AZ in {ctx.region} outside the EKS-unsupported set"
    subnets = [
        sn
        for page in ec2.get_paginator("describe_subnets").paginate(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )
        for sn in page["Subnets"]
    ]
    by_az = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"EKS needs subnets in >=2 available AZs; usable AZs were {sorted(usable)!r} and the "
        f"shared-network subnets cover {sorted(by_az)!r}"
    )
    return [by_az[az] for az in sorted(by_az)][:2]


def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _delete_with_retry(fn, desc):
    """Issue a delete AWS can transiently refuse, retrying the DELETE itself.

    DeleteCluster is refused with ResourceInUseException while EKS still believes an update or a
    dependent object exists, and issuing it once and then polling only the status is how a
    billable control plane leaks while the check still passes: `ctx.on_cleanup` swallows the
    exception and the status never changes because nothing was ever deleted.
    """
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with ResourceInUseException after "
                    f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _teardown_cluster(c, name):
    """Drain dependents, delete the control plane, and poll it to genuinely gone.

    Polled rather than fire-and-forget because the IAM role this check also deletes is the one
    EKS uses to release the cluster's ENIs and security groups: returning before the cluster is
    gone would pull the role out from under its own teardown.
    """
    try:
        for addon in c.list_addons(clusterName=name).get("addons", []):
            try:
                c.delete_addon(clusterName=name, addonName=addon, preserve=False)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_with_retry(lambda: _delete_eks_cluster_retrying(c, name), f"delete cluster {name}")
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _run(cmd, env, timeout_s):
    """Run a native-client subprocess, failing with the data-plane marker on its own wording."""
    proc = subprocess.run(
        cmd, env=env, capture_output=True, text=True, timeout=timeout_s
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: {' '.join(cmd[:3])} failed rc={proc.returncode}: "
            f"{(proc.stderr or proc.stdout)[-600:]}"
        )
    return proc.stdout


def _run_rc(cmd, env, timeout_s):
    """Run a native-client subprocess whose non-zero exit is the observation, not a failure."""
    proc = subprocess.run(
        cmd, env=env, capture_output=True, text=True, timeout=timeout_s
    )
    return proc.returncode, proc.stdout, proc.stderr


def _kube_env(ctx, cluster):
    """A kubeconfig for the check's principal, written by the AWS CLI, in a temp dir we remove.

    `ctx.subprocess_env()` is the ONLY safe source of credentials for a child process: the
    check's keys live on the Context and are deliberately never exported, so a bare
    `subprocess.run` would use the ambient credential chain.
    """
    env = dict(ctx.subprocess_env())
    tmp = tempfile.mkdtemp(prefix="sim2real-kubeconfig-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
    env["KUBECONFIG"] = f"{tmp}/config"
    _run(
        [
            "aws", "eks", "update-kubeconfig",
            "--name", cluster,
            "--region", ctx.region,
            "--kubeconfig", env["KUBECONFIG"],
        ],
        env,
        timeout_s=180,
    )
    return env


def _kubectl_json(env, args, timeout_s=120):
    return json.loads(_run(["kubectl", *args, "-o", "json"], env, timeout_s))


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """The cluster's RBAC authorizer refuses a verb the bound Role never granted, in the API
    server's exact Forbidden sentence, while the granted verb succeeds for the same principal,
    the ConfigMap survives untouched and `kubectl auth can-i` agrees with both."""
    from fidelity_tests_runner import require_tools

    # Every decidable precondition ahead of the first create: a billable control plane must
    # never be provisioned for an answer that was available at import time.
    require_tools("aws", "kubectl")
    c = ctx.client("eks")
    subnets = _fixture_subnets(ctx)

    stem = ctx.unique_name("sim2real-eks-rbac-")
    cluster = stem
    cluster_role = _create_role(
        ctx, f"{stem}-cl", "eks.amazonaws.com", (_EKS_CLUSTER_POLICY,)
    )
    _call_tolerating_role_propagation(
        lambda: c.create_cluster(
            name=cluster,
            roleArn=cluster_role,
            resourcesVpcConfig={
                "subnetIds": subnets,
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            accessConfig={
                "authenticationMode": "API_AND_CONFIG_MAP",
                "bootstrapClusterCreatorAdminPermissions": True,
            },
            tags=dict(_FIXTURE_TAGS),
        ),
        f"create_cluster {cluster}",
    )
    ctx.on_cleanup(lambda: _teardown_cluster(c, cluster))
    described = _wait_for(
        lambda: c.describe_cluster(name=cluster)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {cluster} ACTIVE",
    )
    assert described["status"] == "ACTIVE", (
        f"cluster {cluster} landed in {described['status']!r}; health="
        f"{described.get('health')!r}"
    )

    env = _kube_env(ctx, cluster)
    ns = stem[:60]
    sa = "reader"
    principal = f"system:serviceaccount:{ns}:{sa}"
    payload = f"value-of-{stem}"

    _run(["kubectl", "create", "namespace", ns], env, timeout_s=120)
    ctx.on_cleanup(
        lambda: subprocess.run(
            ["kubectl", "delete", "namespace", ns, "--wait=false"],
            env=env,
            capture_output=True,
            timeout=120,
        )
    )
    _run(["kubectl", "create", "serviceaccount", sa, "-n", ns], env, timeout_s=120)
    _run(
        [
            "kubectl", "create", "role", "cm-reader",
            "-n", ns,
            "--verb", "get",
            "--verb", "list",
            "--resource", "configmaps",
        ],
        env,
        timeout_s=120,
    )
    _run(
        [
            "kubectl", "create", "rolebinding", "cm-reader-binding",
            "-n", ns,
            "--role", "cm-reader",
            "--serviceaccount", f"{ns}:{sa}",
        ],
        env,
        timeout_s=120,
    )
    _run(
        [
            "kubectl", "create", "configmap", "graded",
            "-n", ns,
            "--from-literal", f"key={payload}",
        ],
        env,
        timeout_s=120,
    )
    before = _kubectl_json(env, ["get", "configmap", "graded", "-n", ns])

    # The granted verb, as the bound ServiceAccount: the positive control that proves the
    # binding is live and the refusal below is about the VERB, not about the principal.
    granted = _kubectl_json(
        env, ["get", "configmap", "graded", "-n", ns, "--as", principal]
    )
    assert granted["data"] == {"key": payload}, (
        f"the verb the Role DOES grant did not return the object for {principal!r}: "
        f"data={granted.get('data')!r}"
    )

    # Break exactly one thing: a verb the Role never granted.
    rc, out, err = _run_rc(
        ["kubectl", "delete", "configmap", "graded", "-n", ns, "--as", principal],
        env,
        timeout_s=120,
    )
    assert rc != 0, (
        f"the Kubernetes API server ACCEPTED a delete the bound Role never granted "
        f"(rc={rc}, stdout={out!r}): the ConfigMap was deleted by a principal with get/list only"
    )
    # The API server's Forbidden sentence, asserted clause by clause so the assertion names
    # which part of it a target got wrong. Three clauses, all mandatory: the qualified
    # resource and object name, the principal with the verb it was refused, and the namespace
    # the decision was scoped to. A bare "403 Forbidden" satisfies none of them.
    assert (
        "(Forbidden)" in err
        and 'configmaps "graded" is forbidden:' in err
        and f'User "{principal}" cannot delete resource "configmaps"' in err
        and f'in the namespace "{ns}"' in err
    ), (
        "the refusal did not carry the Kubernetes API server's Forbidden sentence for "
        f"{principal!r} deleting configmaps/graded in {ns!r}; stderr was {err.strip()!r}"
    )

    # The refused verb had no effect: same object, same identity, same data.
    after = _kubectl_json(env, ["get", "configmap", "graded", "-n", ns])
    assert after["metadata"]["uid"] == before["metadata"]["uid"], (
        f"the ConfigMap's uid changed across a refused delete: "
        f"{before['metadata']['uid']!r} -> {after['metadata']['uid']!r}"
    )
    assert after["data"] == {"key": payload}, (
        f"the ConfigMap's data did not survive the refused delete: {after.get('data')!r}"
    )

    # The server's own authorization endpoint must agree with both observations; a hardcoded
    # 403 with no authorizer behind it answers this differently.
    rc_no, verdict_no, _ = _run_rc(
        [
            "kubectl", "auth", "can-i", "delete", "configmaps",
            "-n", ns,
            "--as", principal,
        ],
        env,
        timeout_s=120,
    )
    assert verdict_no.strip() == "no", (
        f"SelfSubjectAccessReview says {verdict_no.strip()!r} (rc={rc_no}) for delete on "
        f"configmaps by {principal!r}, contradicting the Forbidden the API server returned"
    )
    verdict_yes = _run(
        [
            "kubectl", "auth", "can-i", "get", "configmaps",
            "-n", ns,
            "--as", principal,
        ],
        env,
        timeout_s=120,
    )
    assert verdict_yes.strip() == "yes", (
        f"SelfSubjectAccessReview says {verdict_yes.strip()!r} for get on configmaps by "
        f"{principal!r}, contradicting the read that just succeeded"
    )



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
