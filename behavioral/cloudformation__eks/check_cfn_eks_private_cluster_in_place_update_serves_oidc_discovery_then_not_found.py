"""cfn-eks-private-cluster-in-place-update-serves-oidc-discovery-then-not-found."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-eks-private-cluster-in-place-update-serves-oidc-discovery-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "eks"]

#: A control plane takes about 10-15 minutes to create or delete; the cap only stops a hung poll.
_STACK_CAP_S = 1500.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1500.0
#: A tag change and the issuer's discovery document can lag the stack's status.
_PROPAGATE_CAP_S = 300.0
_GONE_CAP_S = 300.0
_POLL_S = 3.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
#: The reason on the extra UPDATE_IN_PROGRESS row CloudFormation may add to an update.
_CONSISTENCY_CHECK = "Eventual consistency check initiated"
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_CLUSTER_POLICY = "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSClusterPolicy"


def _not_found(cluster_name: str) -> tuple[str, str]:
    """EKS's refusal of a cluster that no longer exists."""
    return "ResourceNotFoundException", f"No cluster found for name: {cluster_name}."


def _template(cluster_name: str, subnet_ids: list[str], version: str, step: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ClusterRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "eks.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [{"Fn::Sub": _CLUSTER_POLICY}],
                    },
                },
                # Control plane only, private API endpoint only: nothing is internet-reachable.
                "Cluster": {
                    "Type": "AWS::EKS::Cluster",
                    "Properties": {
                        "Name": cluster_name,
                        "Version": version,
                        "RoleArn": {"Fn::GetAtt": ["ClusterRole", "Arn"]},
                        "ResourcesVpcConfig": {
                            "SubnetIds": subnet_ids,
                            "EndpointPublicAccess": False,
                            "EndpointPrivateAccess": True,
                        },
                        "UpgradePolicy": {"SupportType": "STANDARD"},
                        "Tags": [{"Key": "sim2real-step", "Value": step}],
                    },
                },
            },
            "Outputs": {
                "ClusterRef": {"Value": {"Ref": "Cluster"}},
                "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
                "Endpoint": {"Value": {"Fn::GetAtt": ["Cluster", "Endpoint"]}},
                "Issuer": {"Value": {"Fn::GetAtt": ["Cluster", "OpenIdConnectIssuerUrl"]}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["ClusterRole", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation private EKS cluster reads back as templated and its OIDC issuer serves.

    The discovery document names the issuer DescribeCluster and GetAtt report; a tag change keeps
    the cluster (same ARN and createdAt); delete: ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-cluster.html
    """
    cfn = ctx.client("cloudformation")
    eks = ctx.client("eks")
    network = ctx.network(private=True)
    subnet_ids = list(network.private_subnet_ids)
    cluster_name = ctx.unique_name("sim2real-cfneks-")
    stack_name = ctx.unique_name("sim2real-cfneks-stack-")
    ref = {"stack": stack_name}
    # The region's default Kubernetes version, so the cluster starts in standard support.
    defaults = eks.describe_cluster_versions(defaultOnly=True)["clusterVersions"]
    assert len(defaults) == 1, f"DescribeClusterVersions defaultOnly listed {defaults!r}"
    version = defaults[0]["clusterVersion"]

    # Teardown waits on one deadline of its own: the body's deadline does not bound cleanup.
    # Cleanups run last-registered first: the stack, then the cluster directly should the stack
    # delete have failed, then the stack again so its role goes too.
    limit: dict = {}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))

    # ---- 1. create: CloudFormation's view, EKS's view, and the issuer's discovery document
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(cluster_name, subnet_ids, version, "v1"),
        Tags=_TAGS,
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Cluster"] == cluster_name, (
        f"the cluster's physical id must be its name {cluster_name!r}"
    )
    partition, account = ref["stack"].split(":")[1], ref["stack"].split(":")[4]
    out = _outputs(stack)
    arn = f"arn:{partition}:eks:{ctx.region}:{account}:cluster/{cluster_name}"
    assert (out["ClusterRef"], out["ClusterArn"]) == (cluster_name, arn), (
        f"Ref and GetAtt Arn {(out['ClusterRef'], out['ClusterArn'])!r}, expected {arn!r}"
    )
    cluster = _assert_cluster(eks, cluster_name, out, subnet_ids, network.vpc_id, version)
    _assert_tags(ctx, eks, cluster_name, "v1")
    _assert_discovery(ctx, out["Issuer"])

    # ---- 2. in-place: a new tag value, the same cluster
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(cluster_name, subnet_ids, version, "v2"),
        Tags=_TAGS,
        Capabilities=["CAPABILITY_IAM"],
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Cluster"), cluster_name, "Cluster")
    assert _outputs(stack) == out, f"outputs after the update {_outputs(stack)!r}, before {out!r}"
    after = _assert_cluster(eks, cluster_name, out, subnet_ids, network.vpc_id, version)
    assert after["createdAt"] == cluster["createdAt"], (
        f"an in-place update keeps the cluster: createdAt {cluster['createdAt']!r} became "
        f"{after['createdAt']!r}"
    )
    _assert_tags(ctx, eks, cluster_name, "v2")

    # ---- 3. delete: EKS no longer knows the cluster
    _delete_stack(ctx, cfn, ref["stack"], _STACK_CAP_S)
    got = _wait_error(
        ctx,
        lambda: eks.describe_cluster(name=cluster_name),
        _not_found(cluster_name)[0],
        f"cluster {cluster_name}",
    )
    assert got == _not_found(cluster_name), (
        f"DescribeCluster after the stack delete answered {got!r}"
    )


def _assert_cluster(eks, cluster_name, out, subnet_ids, vpc_id, version) -> dict:
    """DescribeCluster reports the templated settings and the stack's GetAtt values exactly."""
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    vpc = cluster["resourcesVpcConfig"]
    got = {
        "name": cluster["name"],
        "status": cluster["status"],
        "arn": cluster["arn"],
        "version": cluster["version"],
        "endpoint": cluster["endpoint"],
        "issuer": ((cluster.get("identity") or {}).get("oidc") or {}).get("issuer"),
        "roleArn": cluster["roleArn"],
        "subnetIds": sorted(vpc["subnetIds"]),
        "vpcId": vpc["vpcId"],
        "endpointPublicAccess": vpc["endpointPublicAccess"],
        "endpointPrivateAccess": vpc["endpointPrivateAccess"],
        "upgradePolicy": cluster.get("upgradePolicy"),
    }
    want = {
        "name": cluster_name,
        "status": "ACTIVE",
        "arn": out["ClusterArn"],
        "version": version,
        "endpoint": out["Endpoint"],
        "issuer": out["Issuer"],
        "roleArn": out["RoleArn"],
        "subnetIds": sorted(subnet_ids),
        "vpcId": vpc_id,
        "endpointPublicAccess": False,
        "endpointPrivateAccess": True,
        "upgradePolicy": {"supportType": "STANDARD"},
    }
    assert got == want, f"DescribeCluster {cluster_name}: {got!r}, expected {want!r}"
    return cluster


def _assert_tags(ctx, eks, cluster_name: str, step: str) -> None:
    """DescribeCluster tags minus aws:* are the stack's tag plus the template's step tag, polled."""
    want = {"sim2real": CHECK, "sim2real-step": step}
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        tags_now = eks.describe_cluster(name=cluster_name)["cluster"].get("tags") or {}
        got = {k: v for k, v in tags_now.items() if not k.startswith("aws:")}
        if got == want:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {cluster_name} showed {want!r}")
            raise AssertionError(f"cluster {cluster_name} tags {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _assert_discovery(ctx, issuer: str) -> None:
    """The issuer serves its OpenID discovery document and JWKS anonymously over HTTPS.

    Polled: the issuer's documents can lag the cluster becoming ACTIVE.
    """
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        status, raw = _get(ctx, url)
        if status == 200:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {url} served")
            raise AssertionError(f"GET {url} answered {status}: {raw[:300]!r}")
        time.sleep(_POLL_S)
    doc = json.loads(raw)
    got = (doc.get("issuer"), doc.get("jwks_uri"), doc.get("id_token_signing_alg_values_supported"))
    want = (issuer, issuer.rstrip("/") + "/keys", ["RS256"])
    assert got == want, f"discovery document (issuer, jwks_uri, algs) {got!r}, expected {want!r}"
    status, raw = _get(ctx, doc["jwks_uri"])
    assert status == 200, f"GET {doc['jwks_uri']} answered {status}: {raw[:300]!r}"
    keys = json.loads(raw).get("keys") or []
    shapes = {
        (k.get("kty"), k.get("alg"), k.get("use"), bool(k.get("kid")), bool(k.get("n")), k.get("e"))
        for k in keys
    }
    assert shapes == {("RSA", "RS256", "sig", True, True, "AQAB")}, (
        f"the JWKS at {doc['jwks_uri']} must hold RS256 signing keys only, read {keys!r}"
    )


def _delete_cluster(eks, cluster_name: str) -> None:
    """Delete the cluster directly when the stack delete left it; not-found is already deleted."""
    try:
        eks.delete_cluster(name=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get(ctx, url: str) -> tuple[int, bytes]:
    """GET ``url`` on the target with no credentials; (status, body)."""
    target, headers = ctx.endpoint_route(url)
    request = urllib.request.Request(target, headers={"Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(
            request, timeout=30, context=_https_context(ctx.http_verify)
        ) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        # DNS, reset or timeout: no answer, which the caller's poll retries like a non-200.
        return 0, repr(getattr(exc, "reason", exc)).encode()


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(
            cafile=verify if isinstance(verify, str) and verify else None
        )
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. With ctx None (teardown) it is cap_s.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*.

    CloudFormation may add one UPDATE_IN_PROGRESS row for its eventual consistency check.
    """
    statuses = [status for status, _, _ in rows]
    reasons = [reason for _, reason, _ in rows]
    plain = statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"]
    checked = statuses == ["UPDATE_IN_PROGRESS", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"] and (
        reasons[1] == _CONSISTENCY_CHECK
    )
    assert (plain or checked) and reasons[0] != _REPLACING, (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str, cap_s: float) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, cap_s), "DELETE_COMPLETE")


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _teardown_stack(cfn, ref: dict, limit: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Every wait shares the one deadline in *limit*, so the whole teardown fits its cap.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"], _remaining(limit))
    _delete_stack(None, cfn, stack["StackId"], _remaining(limit))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
