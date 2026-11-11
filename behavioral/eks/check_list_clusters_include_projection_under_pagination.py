"""list-clusters-include-projection-under-pagination."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-clusters-include-projection-under-pagination"
GROUP = 'state'
SERVICES = ['eks']

# ListClustersRequestMaxResults is @range{min 1, max 100}; clusters is a flat list
# of names, so at maxResults=1 every non-terminal page must hold exactly one name.
_PAGE_LIMIT = 400


def _error(fn):
    """Call fn; require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _cluster_exists(c, name):
    """True while DescribeCluster still returns the cluster, False once it is not found."""
    try:
        c.describe_cluster(name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise
    return True


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


def _safe_deregister(c, name):
    """Idempotent teardown: a cluster already deregistered in-body is not an error."""
    try:
        c.deregister_cluster(name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _register_connected_cluster(ctx, *, timeout_s=240):
    """RegisterCluster with a fresh connector role; returns the cluster dict."""
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
            # IAM propagation lag of the fresh connector role surfaces as these codes.
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
    return resp["cluster"]


def _walk_clusters(c, *, page_size=None, include=None):
    """Fully paginate ListClusters; return (pages, flattened_names)."""
    pages = []
    token = None
    while True:
        kwargs = {}
        if page_size is not None:
            kwargs["maxResults"] = page_size
        if include is not None:
            kwargs["include"] = list(include)
        if token:
            kwargs["nextToken"] = token
        resp = c.list_clusters(**kwargs)
        pages.append(resp.get("clusters", []))
        token = resp.get("nextToken")
        if not token:
            break
        assert len(pages) <= _PAGE_LIMIT, (
            f"ListClusters pagination did not terminate within {_PAGE_LIMIT} pages "
            f"at maxResults={page_size!r} include={include!r}"
        )
    flat = [n for page in pages for n in page]
    return pages, flat


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClusters applies include on every page, maxResults=1 pages the flat name list exactly,
    and an uppercase include=["ALL"] is refused rather than case-folded.

    Reference: https://docs.aws.amazon.com/eks/latest/APIReference/API_ListClusters.html
    """
    c = ctx.client("eks")
    cluster = _register_connected_cluster(ctx)
    name = cluster["name"]

    # Default projection excludes connected clusters, on every page.
    default_pages, default_names = _walk_clusters(c, page_size=1)
    for i, page in enumerate(default_pages):
        assert name not in page, (
            f"connected cluster {name!r} leaked onto page {i} of the DEFAULT "
            f"ListClusters projection, which must contain only Amazon EKS clusters"
        )
    assert name not in default_names, default_names[:20]

    # Two unpaginated snapshots bracket the paginated walk so concurrent cluster
    # churn in the account cannot make the comparison flaky.
    _p, all_before = _walk_clusters(c, page_size=100, include=["all"])
    assert name in all_before, (
        f"{name!r} is missing from ListClusters(include=['all']) immediately "
        f"after RegisterCluster returned it"
    )

    paged_pages, paged = _walk_clusters(c, page_size=1, include=["all"])
    _p, all_after = _walk_clusters(c, page_size=100, include=["all"])

    assert len(paged) == len(set(paged)), (
        f"maxResults=1 pagination returned a duplicate cluster name: "
        f"{sorted(n for n in set(paged) if paged.count(n) > 1)!r}"
    )
    assert name in paged, (
        f"{name!r} is present unpaginated but was DROPPED by the maxResults=1 walk "
        f"({len(paged)} names over {len(paged_pages)} pages)"
    )
    stable = set(all_before) & set(all_after)
    assert stable <= set(paged), (
        f"the maxResults=1 walk dropped clusters that were present before AND "
        f"after it: {sorted(stable - set(paged))!r}"
    )
    assert set(paged) <= set(all_before) | set(all_after), (
        f"the maxResults=1 walk invented clusters absent from both unpaginated "
        f"snapshots: {sorted(set(paged) - (set(all_before) | set(all_after)))!r}"
    )
    for i, page in enumerate(paged_pages[:-1]):
        assert len(page) == 1, (
            f"maxResults=1 non-terminal page {i} returned {len(page)} names "
            f"({page!r}); clusters is a flat name list so the page size is exact"
        )
    assert len(paged_pages[-1]) <= 1, (
        f"maxResults=1 terminal page returned {len(paged_pages[-1])} names"
    )

    # The include token is documented lowercase-only. EKS refuses it with
    # InvalidRequestException, the same code and message an entirely unknown token gets, so it
    # validates the include list as a set membership test and does not case-fold.
    include_message = "One or more values in the 'include' parameter is not valid"
    code, message = _error(lambda: c.list_clusters(include=["ALL"]))
    assert code == "InvalidRequestException", (
        f"include=['ALL'] returned {code}; 'all' is lowercase-only, so an uppercase token must "
        f"be refused with InvalidRequestException and not silently case-folded into the "
        f"connected-cluster projection"
    )
    assert message == include_message, f"message: {message!r} != {include_message!r}"
    # An entirely unknown token is refused identically -- the uppercase token is not a special
    # case, it simply is not a member of the accepted set.
    bogus_code, bogus_message = _error(lambda: c.list_clusters(include=["sim2real-behav-bogus"]))
    assert bogus_code == "InvalidRequestException", (
        f"an unknown include token must be refused with InvalidRequestException; got "
        f"{bogus_code}"
    )
    assert bogus_message == include_message, (
        f"message: {bogus_message!r} != {include_message!r}"
    )
    # An EMPTY include list, by contrast, is accepted and means the default projection.
    empty_include = c.list_clusters(include=[])
    assert name not in empty_include.get("clusters", []), (
        f"include=[] must behave as the DEFAULT projection and exclude the connected cluster "
        f"{name!r}; got {empty_include.get('clusters')!r}"
    )
    # Effect absent: the refusal did not quietly widen the default projection.
    _p, still_default = _walk_clusters(c, page_size=100)
    assert name not in still_default, (
        f"after a refused include=['ALL'], {name!r} appeared in the default "
        f"projection"
    )
    _p, control = _walk_clusters(c, page_size=100, include=["all"])
    assert name in control, (
        f"{name!r} vanished from include=['all'] after a refused include=['ALL']"
    )

    # Deregistration must remove it from BOTH projections.
    deregistered = c.deregister_cluster(name=name)["cluster"]
    assert deregistered["name"] == name, deregistered
    assert deregistered["status"] == "DELETING", (
        f"DeregisterCluster must report the cluster as DELETING, got {deregistered['status']!r}"
    )
    _wait_for(
        lambda: _cluster_exists(c, name),
        lambda exists: not exists,
        # Deregistration is a control-plane record deletion with no infrastructure to tear down.
        timeout_s=300,
        interval_s=10,
        desc=f"connected cluster {name} to disappear",
    )
    not_found_message = f"No cluster found for name: {name}."
    code, message = _error(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", code
    assert message == not_found_message, f"message: {message!r} != {not_found_message!r}"
    _p, gone_all = _walk_clusters(c, page_size=100, include=["all"])
    assert name not in gone_all, (
        f"{name!r} is still in ListClusters(include=['all']) after DescribeCluster "
        f"reports it gone"
    )
    # A mutation on the now-dead id fails the same specific way as the read.
    code, message = _error(lambda: c.deregister_cluster(name=name))
    assert code == "ResourceNotFoundException", (
        f"a second DeregisterCluster on the vanished cluster {name!r} returned {code}"
    )
    assert message == not_found_message, f"message: {message!r} != {not_found_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
