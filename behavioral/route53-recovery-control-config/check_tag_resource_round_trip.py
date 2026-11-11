"""tag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-round-trip"
GROUP = "state"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource; UntagResource
    removes exactly the specified key, leaving the rest intact."""
    client = ctx.client("route53-recovery-control-config")

    cluster_arn = _get_or_create_shared_cluster(ctx, client)

    client.tag_resource(ResourceArn=cluster_arn, Tags={"env": "sim2real-behav", "keep": "yes"})
    ctx.on_cleanup(
        lambda: _safe_call(lambda: client.untag_resource(ResourceArn=cluster_arn, TagKeys=["env", "keep"]))
    )

    tags = client.list_tags_for_resource(ResourceArn=cluster_arn)["Tags"]
    assert tags == {"env": "sim2real-behav", "keep": "yes"}, tags

    client.untag_resource(ResourceArn=cluster_arn, TagKeys=["env"])

    tags = client.list_tags_for_resource(ResourceArn=cluster_arn)["Tags"]
    assert tags == {"keep": "yes"}, tags


# ===== helpers =====
_SHARED_CLUSTER_NAME = "sim2real-behav-r53arc-shared"


def _get_or_create_shared_cluster(ctx, client):
    """Find-or-create a long-lived cluster shared across checks in this suite. The
    account's cluster quota is only 2, so most checks must NOT each create their own
    cluster; they share one DEPLOYED cluster (deleted in teardown by whichever check
    finds it holding nothing else) and only create/delete their
    own child resources (control panels, routing controls, safety rules) within it."""
    import time

    from botocore.exceptions import ClientError

    def _find():
        for page in client.get_paginator("list_clusters").paginate():
            for c in page["Clusters"]:
                if c["Name"] == _SHARED_CLUSTER_NAME and c["Status"] != "PENDING_DELETION":
                    return c["ClusterArn"]
        return None

    arn = _find()
    if arn is None:
        deadline = time.monotonic() + 250.0
        while arn is None:
            try:
                arn = client.create_cluster(ClusterName=_SHARED_CLUSTER_NAME)["Cluster"][
                    "ClusterArn"
                ]
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "ConflictException":
                    arn = _find()
                    if arn is None:
                        raise
                elif code == "ServiceQuotaExceededException" and time.monotonic() < deadline:
                    time.sleep(2.0)
                else:
                    raise


    ctx.on_cleanup(lambda: _delete_shared_cluster(client, arn))
    deadline = time.monotonic() + 420.0
    cluster = None
    while time.monotonic() < deadline:
        cluster = client.describe_cluster(ClusterArn=arn)["Cluster"]
        if cluster["Status"] == "DEPLOYED":
            return arn
        time.sleep(5.0)
    raise AssertionError(f"shared cluster did not reach DEPLOYED in time (last: {cluster!r})")


def _safe_call(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_own(delete, timeout_s=300.0, interval_s=5.0) -> None:
    """Teardown: delete one resource this check created. A refusal while the resource's own
    children are still deleting (ConflictException, ValidationException) is retried; not found
    is success; a timeout or any other error raises, so nothing of the check's is left silently."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_shared_cluster(client, arn, timeout_s=600.0, interval_s=5.0) -> None:
    """Teardown for the shared cluster, registered by every check that uses it: a cluster bills by
    the hour, so it must never be left without an owner. The check's own cleanups have already
    deleted its control panels, routing controls and safety rules. This waits, within a bounded
    window, until the cluster holds no non-default control panel and no routing control other
    than ones being deleted, then deletes the cluster and waits until it is gone; it deletes
    nothing else. A non-default control panel or a live routing control still there after 60 s
    belongs to another check, whose own teardown deletes the cluster; this teardown then raises
    naming what holds the cluster, so the check's cleanup detail reports it."""
    import time

    from botocore.exceptions import ClientError

    def _holders():
        held, deleting = [], []
        for page in client.get_paginator("list_control_panels").paginate(ClusterArn=arn):
            for panel in page.get("ControlPanels", []):
                if not panel.get("DefaultControlPanel"):
                    side = deleting if panel.get("Status") == "PENDING_DELETION" else held
                    side.append(panel["ControlPanelArn"])
                    continue
                rcs = client.get_paginator("list_routing_controls").paginate(
                    ControlPanelArn=panel["ControlPanelArn"]
                )
                for rc_page in rcs:
                    for rc in rc_page.get("RoutingControls", []):
                        side = deleting if rc.get("Status") == "PENDING_DELETION" else held
                        side.append(rc["RoutingControlArn"])
        return held, deleting

    deadline = time.monotonic() + timeout_s
    held_until = time.monotonic() + 60.0
    while True:
        try:
            held, deleting = _holders()
            if held and time.monotonic() >= held_until:
                raise AssertionError(
                    f"shared cluster {arn} left in place for the check that holds it: "
                    f"{len(held)} control panel(s)/routing control(s) not created by this check "
                    f"remain: {held}"
                )
            if not held and not deleting:
                client.delete_cluster(ClusterArn=arn)
                break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"shared cluster {arn} not deleted: children still deleting after {timeout_s}s: "
                f"{deleting}"
            )
        time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            client.describe_cluster(ClusterArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"shared cluster {arn} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
