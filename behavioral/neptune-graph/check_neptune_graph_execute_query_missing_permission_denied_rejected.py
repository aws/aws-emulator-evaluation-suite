"""neptune-graph-execute-query-missing-permission-denied-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "neptune-graph-execute-query-missing-permission-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM principal with no attached policies gets AccessDeniedException calling ExecuteQuery; the
    original caller (with real permissions) still succeeds on the same graph (positive control)."""
    ng = ctx.client("neptune-graph")
    iam = ctx.client("iam")
    graph_id = _create_available_graph(ctx, ng)

    user_name = ctx.unique_name("sim2real-ng-nopolicy-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: _delete_user(iam, user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    # ExecuteQuery is data plane: on real AWS the client resolves the graph's own
    # `g-<id>.<region>.neptune-graph.amazonaws.com` host from the endpoint ruleset.
    denied_client = ctx.client(
        "neptune-graph",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    # Two independent sources of transient failure sit between "graph AVAILABLE" and a clean
    # authorization decision: freshly-minted IAM credentials can take a few seconds to propagate
    # (surfacing as InvalidClientTokenId), and the graph's own per-resource data-plane hostname
    # (g-<id>.<region>.neptune-graph.amazonaws.com) is not always resolvable the instant the
    # control plane reports AVAILABLE (surfacing as EndpointConnectionError). Poll through both
    # until the real authorization outcome itself is observed.
    code, message = _poll_until(
        lambda: _error(
            lambda: denied_client.execute_query(
                graphIdentifier=graph_id, queryString="RETURN 1 AS one", language="OPEN_CYPHER"
            )
        ),
        # A fresh key is first refused as "Authentication Failed" while it propagates; the
        # authorization decision is the denial that names the principal and the graph.
        lambda err: err[0] == "AccessDeniedException" and err[1] != "Authentication Failed",
        timeout_s=1200,
        interval_s=10,
    )
    assert code == "AccessDeniedException", code
    account = ctx.account
    assert message == (
        f"User: arn:aws:iam::{account}:user/{user_name} is not authorized to perform:"
        " neptune-graph:DeleteDataViaQuery, neptune-graph:ReadDataViaQuery,"
        " neptune-graph:WriteDataViaQuery on resource:"
        f" arn:aws:neptune-graph:{ctx.region}:{account}:graph/{graph_id}"
    ), message

    # Positive control: the properly-permissioned caller still succeeds on the same graph. Same
    # endpoint-resolution lag can hit this call too, so retry through it rather than the IAM poll's
    # window alone.
    resp = _poll_until(
        lambda: _call_tolerating_endpoint_lag(
            lambda: ng.execute_query(
                graphIdentifier=graph_id, queryString="RETURN 1 AS one", language="OPEN_CYPHER"
            )
        ),
        lambda r: r is not None,
        timeout_s=1200,
        interval_s=10,
    )
    data = json.loads(resp["payload"].read())
    assert data["results"] == [{"one": 1}], data


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so an over-permissive target cannot pass as a transient."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    except EndpointConnectionError:
        return "EndpointNotReady", None
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


def _call_tolerating_endpoint_lag(fn):
    try:
        return fn()
    except EndpointConnectionError:
        return None


def _poll_until(probe, predicate, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_user(iam, user_name):
    try:
        for key in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_available_graph(ctx, ng, memory=16, deletion_protection=False):
    name = ctx.unique_name("sim2real-ng-")
    graph_id = ng.create_graph(
        graphName=name,
        provisionedMemory=memory,
        deletionProtection=deletion_protection,
        publicConnectivity=True,
    )["id"]

    def _cleanup():
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] in ("AVAILABLE", "FAILED", "STOPPED"),
                timeout_s=timeout_s,
                interval_s=2,
            )

        try:
            if _settle(900).get("deletionProtection"):
                ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
                _settle(120)
            ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    if status != "AVAILABLE":
        raise AssertionError(f"graph {graph_id} did not reach AVAILABLE, got {status}")
    return graph_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
