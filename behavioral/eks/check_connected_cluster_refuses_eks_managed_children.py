"""connected-cluster-refuses-eks-managed-children."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connected-cluster-refuses-eks-managed-children"
GROUP = 'overly-permissive'
SERVICES = ['eks']


# A CONNECTED cluster (RegisterCluster) provisions no control plane, EC2 or VPC objects: it
# materialises in seconds and bills nothing, unlike a per-hour-billed CreateCluster.


def _error_code(fn):
    """Call fn; return the botocore error Code, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _expect_error(fn):
    """Call fn, require that it raises, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {desc}; last={val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get(
            "AttachedPolicies", []
        ):
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
        Description="candidates_09 eks fidelity check: EKS connector role",
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


def _register_connected_cluster(ctx, *, tags_map=None, client_request_token=None,
                                timeout_s=240):
    """RegisterCluster with a fresh connector role, tolerating IAM propagation.

    Returns (cluster_dict, role_arn). Teardown (DeregisterCluster) is registered
    before the name is used anywhere else.
    """
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-connected-")
    role_arn = _create_connector_role(ctx)
    kwargs = {"name": name, "connectorConfig": {"roleArn": role_arn, "provider": "OTHER"}}
    if tags_map:
        kwargs["tags"] = dict(tags_map)
    if client_request_token:
        kwargs["clientRequestToken"] = client_request_token
    ctx.on_cleanup(lambda: c.deregister_cluster(name=name))

    def attempt():
        try:
            return c.register_cluster(**kwargs)
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
    return resp["cluster"], role_arn


def _a_supported_version(c) -> str:
    """A currently-supported, non-default Kubernetes version from the catalogue."""
    versions = c.describe_cluster_versions().get("clusterVersions", [])
    supported = [
        v["clusterVersion"]
        for v in versions
        if v.get("versionStatus") in ("STANDARD_SUPPORT", "EXTENDED_SUPPORT")
    ]
    assert supported, f"DescribeClusterVersions returned nothing supported: {versions!r}"
    return supported[0]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A connected cluster refuses every EKS-managed child op (create and read) with ClientException
    and its exact message, creates nothing, still validates payloads first, and stays intact.
    """
    c = ctx.client("eks")
    cluster, role_arn = _register_connected_cluster(ctx, tags_map={"sim2real": "1"})
    name = cluster["name"]
    assert cluster.get("connectorConfig"), (
        f"RegisterCluster returned no connectorConfig, so this is not a connected "
        f"cluster: {cluster!r}"
    )
    version = _a_supported_version(c)
    _GATE_CODE = "ClientException"
    _GATE_MSG = "This operation is not supported for connected clusters"

    # Each body below is fully valid in isolation: a real catalogue add-on name,
    # a real IAM role ARN, a real supported Kubernetes version, a real log type.
    # The read-side operations need no payload at all beyond the cluster name.
    illegal = {
        "CreateAddon": lambda: c.create_addon(clusterName=name, addonName="vpc-cni"),
        "CreateAccessEntry": lambda: c.create_access_entry(
            clusterName=name, principalArn=role_arn
        ),
        "UpdateClusterVersion": lambda: c.update_cluster_version(
            name=name, version=version
        ),
        "UpdateClusterConfig": lambda: c.update_cluster_config(
            name=name,
            logging={"clusterLogging": [{"types": ["api"], "enabled": True}]},
        ),
        "ListAddons": lambda: c.list_addons(clusterName=name),
        "ListNodegroups": lambda: c.list_nodegroups(clusterName=name),
        "ListAccessEntries": lambda: c.list_access_entries(clusterName=name),
        "DescribeAddon": lambda: c.describe_addon(clusterName=name, addonName="vpc-cni"),
        "DescribeAccessEntry": lambda: c.describe_access_entry(
            clusterName=name, principalArn=role_arn
        ),
    }
    observed = {}
    for op, fn in illegal.items():
        code, msg = _expect_error(fn)
        observed[op] = (code, msg)
        assert code == _GATE_CODE, (
            f"{op} on connected cluster {name} -> {code}: {msg}. Expected "
            f"{_GATE_CODE} (the operation is not supported for a cluster EKS does "
            f"not manage). ResourceNotFoundException here would mean the emulator "
            f"failed to resolve a cluster that demonstrably exists; a success would "
            f"mean it served or attached a child for a control plane that does not "
            f"exist. Observed so far: {observed}"
        )
        assert msg == _GATE_MSG, (
            f"{op} must be refused with the connected-cluster message {_GATE_MSG!r}, "
            f"which is what distinguishes this gate from every other ClientException "
            f"EKS raises; got {msg!r}"
        )

    # The gate is not a blanket ClientException for the cluster: PAYLOAD validation still runs
    # first. A CreateFargateProfile missing its required selectors is refused on VALIDATION, not
    # by the gate -- so an emulator cannot pass the block above by short-circuiting every
    # connected-cluster call.
    fp_code, fp_msg = _expect_error(
        lambda: c.create_fargate_profile(
            fargateProfileName=ctx.unique_name("sim2real-behav-fp-"),
            clusterName=name,
            podExecutionRoleArn=role_arn,
        )
    )
    assert fp_code == "InvalidParameterException", (
        f"CreateFargateProfile with no selectors on connected cluster {name} -> {fp_code}: "
        f"{fp_msg}. Real AWS validates the payload BEFORE applying the connected-cluster gate, "
        f"so the refusal must be InvalidParameterException, not {_GATE_CODE}"
    )
    assert "selector" in fp_msg.lower(), (
        f"the validation refusal must name the missing selectors; got {fp_msg!r}"
    )

    # A ghost cluster is still distinguished from a connected one: the SAME operation against a
    # name that does not exist is ResourceNotFoundException, not the gate. Without this an
    # emulator could return the gate error for everything.
    ghost = ctx.unique_name("sim2real-behav-ghost-")
    ghost_code, ghost_msg = _expect_error(
        lambda: c.create_addon(clusterName=ghost, addonName="vpc-cni")
    )
    assert ghost_code == "ResourceNotFoundException", (
        f"CreateAddon against the nonexistent cluster {ghost!r} -> {ghost_code}: {ghost_msg}; "
        f"a connected cluster and an absent cluster must not answer identically"
    )

    # Effect absent. Describe/List are refused by the same gate on a connected cluster, so
    # absence is established by REPLAYING the refused creates: had either one
    # materialised its child, the replay would be ResourceInUseException.
    for op, fn in (
        ("CreateAddon", illegal["CreateAddon"]),
        ("CreateAccessEntry", illegal["CreateAccessEntry"]),
    ):
        code, msg = _expect_error(fn)
        assert (code, msg) == (_GATE_CODE, _GATE_MSG), (
            f"replaying the refused {op} on {name} returned {code}: {msg}. A second identical "
            f"refusal is the proof that the first call created nothing -- ResourceInUseException "
            f"here would mean the child was materialised despite the refusal"
        )

    # Control: the connected cluster itself is untouched and still readable, and still visible in
    # exactly the projection that lists connected clusters.
    after = c.describe_cluster(name=name)["cluster"]
    assert after["name"] == name, after
    assert after.get("connectorConfig"), (
        f"connectorConfig disappeared after the refusals: {after!r}"
    )
    assert after["status"] == cluster["status"], (
        f"connected cluster status drifted from {cluster['status']!r} to "
        f"{after['status']!r} across the refused operations"
    )
    listed = []
    token = None
    while True:
        kwargs = {"include": ["all"], "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = c.list_clusters(**kwargs)
        listed.extend(page.get("clusters", []))
        token = page.get("nextToken")
        if not token or len(listed) > 10000:
            break
    assert name in listed, (
        f"{name!r} vanished from ListClusters(include=['all']) after the refused operations "
        f"({len(listed)} clusters listed)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
