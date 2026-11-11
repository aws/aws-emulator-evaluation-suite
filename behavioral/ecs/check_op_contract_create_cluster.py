"""op-contract-createCluster."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "op-contract-createCluster"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster echoes containerInsights disabled as DescribeClusters confirms and stores a real
    Cloud Map namespace ARN in serviceConnectDefaults; a nonexistent namespace ARN is refused
    NamespaceNotFoundException with the relayed message and lists no cluster."""
    ecs = ctx.client("ecs")

    name = ctx.unique_name("sim2real-behav-cluster-")
    resp = ecs.create_cluster(
        clusterName=name,
        settings=[{"name": "containerInsights", "value": "disabled"}],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    cluster = resp["cluster"]
    assert cluster["clusterName"] == name, f"expected clusterName {name}, got {cluster['clusterName']}"
    assert cluster["status"] in ("ACTIVE", "PROVISIONING"), f"expected ACTIVE/PROVISIONING, got {cluster['status']}"
    assert {"name": "containerInsights", "value": "disabled"} in cluster["settings"], (
        f"expected containerInsights=disabled in {cluster['settings']}"
    )

    described = ecs.describe_clusters(clusters=[name], include=["SETTINGS", "TAGS"])["clusters"][0]
    assert described["status"] == "ACTIVE", f"expected ACTIVE on independent read, got {described['status']}"
    assert {"name": "containerInsights", "value": "disabled"} in described["settings"], (
        f"expected containerInsights=disabled on independent read, got {described['settings']}"
    )
    assert {"key": "sim2real", "value": "true"} in described["tags"], (
        f"expected sim2real=true tag on independent read, got {described['tags']}"
    )

    # Positive control on the SAME wiring as the negative below: a well-formed namespace ARN that
    # actually resolves must be accepted and reflected. Without this, "rejects a bogus namespace
    # ARN" would be indistinguishable from "rejects every ARN-shaped
    # serviceConnectDefaults.namespace value".
    namespace_id, namespace_arn = _create_http_namespace(ctx)
    good_name = ctx.unique_name("sim2real-behav-cluster-sc-")
    good_cluster = ecs.create_cluster(
        clusterName=good_name, serviceConnectDefaults={"namespace": namespace_arn}
    )["cluster"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=good_name))
    assert good_cluster.get("serviceConnectDefaults", {}).get("namespace") == namespace_arn, (
        f"expected serviceConnectDefaults.namespace {namespace_arn}, got {good_cluster.get('serviceConnectDefaults')}"
    )
    described_good = ecs.describe_clusters(clusters=[good_name])["clusters"][0]
    assert described_good.get("serviceConnectDefaults", {}).get("namespace") == namespace_arn, (
        f"expected serviceConnectDefaults.namespace {namespace_arn} on independent read, "
        f"got {described_good.get('serviceConnectDefaults')}"
    )

    # A namespace ARN scoped to a fabricated placeholder account (123456789012) never reaches
    # ECS's "does this namespace exist" check: the account mismatch trips authorization first,
    # yielding AccessDeniedException instead of NamespaceNotFoundException. Use the CALLER's own
    # account (so the ARN is authorization-valid) with a well-formed but nonexistent namespace ID
    # (Cloud Map IDs are "ns-" + 16 lowercase hex/alnum chars) so the lookup genuinely 404s.
    account_id = _caller_account_id(ctx)
    bogus_ns_arn = f"arn:aws:servicediscovery:{ctx.region}:{account_id}:namespace/ns-0000000000abcdef"
    failed_name = ctx.unique_name("sim2real-behav-cluster-bad-")
    err, message = _error(
        lambda: ecs.create_cluster(
            clusterName=failed_name,
            serviceConnectDefaults={"namespace": bogus_ns_arn},
        )
    )
    assert err == "NamespaceNotFoundException", f"expected NamespaceNotFoundException, got {err}"
    # ECS relays Service Discovery's error text, which carries a per-request id and ECS's own
    # attempt count: mask only those two values.
    assert re.sub(r"Request ID: [0-9A-Fa-f-]+\) \(SDK Attempt Count: \d+\)",
                  "Request ID: <id>) (SDK Attempt Count: <n>)", message) == (
        "Service returned error code NamespaceNotFound (Service: ServiceDiscovery, Status Code: 400, "
        "Request ID: <id>) (SDK Attempt Count: <n>)"
    ), f"expected the relayed Service Discovery NamespaceNotFound message, got {message!r}"

    listed = ecs.list_clusters()["clusterArns"]
    assert not any(failed_name in arn for arn in listed), (
        f"expected {failed_name} absent from list_clusters after rejected create, got {listed}"
    )


def _caller_account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_http_namespace(ctx, *, timeout_s=60):
    """Create a Cloud Map HTTP namespace (no VPC dependency); waits for the async
    CreateHttpNamespace operation to finish and returns (namespace_id, namespace_arn).
    """
    import time

    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ecs-ns-")
    op_id = sd.create_http_namespace(Name=ns_name, Tags=[{"Key": "sim2real", "Value": "true"}])[
        "OperationId"
    ]
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=op_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            break
        time.sleep(3)
    else:
        raise AssertionError(f"timed out waiting for Cloud Map CreateHttpNamespace (last={op!r})")
    if op["Status"] != "SUCCESS":
        raise AssertionError(f"Cloud Map namespace creation failed: {op.get('ErrorMessage')}")
    namespace_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=namespace_id))
    namespace_arn = sd.get_namespace(Id=namespace_id)["Namespace"]["Arn"]
    return namespace_id, namespace_arn


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
