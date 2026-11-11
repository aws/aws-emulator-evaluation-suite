"""list-clusters-pagination-invariants."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "list-clusters-pagination-invariants"
GROUP = 'cluster-listing'
SERVICES = ['eks']


# RegisterCluster mints a real cluster resource
# with no control plane, no EC2 and no hourly charge.


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
        Description="sim2real eks fidelity check: EKS connector role",
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


def _safe_deregister(c, name):
    """Idempotent teardown: a cluster already deregistered in-body is not an error."""
    try:
        c.deregister_cluster(name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _register_connected_cluster(ctx, *, timeout_s=240):
    """RegisterCluster with a fresh connector role; returns the new cluster's name."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-connected-")
    role_arn = _create_connector_role(ctx)
    # Registered BEFORE the create call so a cluster minted by a request whose
    # response is lost is still torn down.
    ctx.on_cleanup(lambda: _safe_deregister(c, name))

    def attempt():
        try:
            return c.register_cluster(
                name=name,
                connectorConfig={"roleArn": role_arn, "provider": "OTHER"},
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

    _wait_for(
        attempt,
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=5,
        desc="RegisterCluster accepted (connector role propagation)",
    )
    return name


def _walk(c, *, max_results):
    """Fully paginate ListClusters(include=['all']); return (pages, flattened_names)."""
    pages: list[list[str]] = []
    token = None
    while True:
        kwargs: dict = {"include": ["all"]}
        if max_results is not None:
            kwargs["maxResults"] = max_results
        if token:
            kwargs["nextToken"] = token
        resp = c.list_clusters(**kwargs)
        pages.append(resp.get("clusters", []))
        token = resp.get("nextToken")
        if not token:
            break
        assert len(pages) <= 200, "pagination did not terminate"
    return pages, [n for page in pages for n in page]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With two registered connected clusters, ListClusters at maxResults=1 returns at most one name per page over at
    least two pages, never repeats a name, ends without nextToken, and lists both clusters, as the unpaginated
    call does."""
    c = ctx.client("eks")
    created = {_register_connected_cluster(ctx), _register_connected_cluster(ctx)}

    unpaginated = set(c.list_clusters(maxResults=100, include=["all"]).get("clusters", []))
    assert created <= unpaginated, (
        f"registered clusters {sorted(created)} missing from the unpaginated listing "
        f"{sorted(unpaginated)}"
    )

    pages, seen = _walk(c, max_results=1)
    for i, page in enumerate(pages):
        assert len(page) <= 1, f"maxResults=1 not honoured on page {i}, got {len(page)}"

    # Terminal page carried no continuation token (loop exit condition), and
    # the cursor never replayed a name.
    assert len(seen) == len(set(seen)), f"duplicate names across pages: {seen}"
    assert created <= set(seen), (
        f"registered clusters {sorted(created)} were dropped by the maxResults=1 walk "
        f"({sorted(seen)})"
    )
    assert set(seen) & created == unpaginated & created, (
        f"paginated walk {sorted(seen)} and unpaginated {sorted(unpaginated)} disagree on "
        f"the registered clusters {sorted(created)}"
    )
    assert len(pages) >= 2, (
        f"only {len(pages)} page(s) at maxResults=1 with {len(seen)} cluster(s) present; "
        f"the two registered clusters should have forced a multi-page walk"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
