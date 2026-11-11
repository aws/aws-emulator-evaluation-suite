"""access-denied-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53-recovery-cluster"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """GetRoutingControlState from a role whose policy explicitly denies it is refused with
    AccessDeniedException, while the unrestricted credentials read the same control; once the Deny
    is removed the same role session reads it too.
    """
    cfg = ctx.client("route53-recovery-control-config")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    cluster_arn, _panel_arn = _get_or_create_shared_cluster(ctx, cfg)
    cluster = _cluster_data_client(ctx, cfg, cluster_arn)

    _rc_name, rc_arn = _create_routing_control(ctx, cfg, cluster_arn)
    cluster.update_routing_control_state(RoutingControlArn=rc_arn, RoutingControlState="On")
    _wait_for_control_state(cluster, rc_arn, "On")

    role_name = ctx.unique_name("sim2real-arc-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    # Two SEPARATE inline policies, not one document with both statements: the restore step
    # below deletes only the deny policy; a single policy holding both statements would remove
    # the Allow along with the Deny, and the call would then be denied for lack of any allow
    # ("no identity-based policy allows this action") instead of being restored.
    allow_policy_name = "allow-route53-recovery-cluster"
    deny_policy_name = "deny-get-routing-control-state"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=allow_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "route53-recovery-cluster:*",
                    "Resource": "*",
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: _remove_role_policy(iam, role_name, allow_policy_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=deny_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "route53-recovery-cluster:GetRoutingControlState",
                    "Resource": "*",
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: _remove_role_policy(iam, role_name, deny_policy_name))

    creds = _assume_role_with_retry(sts, role_arn)
    denied_client = ctx.client(
        "route53-recovery-cluster",
        endpoint_url=cluster.meta.endpoint_url,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    code, message = _error(lambda: denied_client.get_routing_control_state(RoutingControlArn=rc_arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/sim2real-arc-deny-check "
        f"is not authorized to perform: route53-recovery-cluster:GetRoutingControlState on "
        f"resource: {rc_arn} with an explicit deny in an identity-based policy"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Positive control: the normal (unrestricted) caller can still read the state -- proves the
    # account/cluster are otherwise healthy, so the denial above is not "everything is broken".
    resp = cluster.get_routing_control_state(RoutingControlArn=rc_arn)
    assert resp["RoutingControlState"] == "On", (
        f"the unrestricted caller must still read the routing control state while the assumed "
        f"role is denied; expected 'On', got {resp['RoutingControlState']!r}"
    )

    # Restore: remove the specific Deny statement and demand the IDENTICAL call, from the SAME
    # assumed-role identity that was just denied, now succeeds. Without this beat, "the Deny
    # statement caused the AccessDeniedException" is indistinguishable from "this assumed-role
    # session can never call GetRoutingControlState at all", which the positive control above
    # (a different, unrestricted principal) cannot rule out.
    _remove_role_policy(iam, role_name, deny_policy_name)
    restored = _poll_until_success(
        lambda: denied_client.get_routing_control_state(RoutingControlArn=rc_arn),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert restored["RoutingControlState"] == "On", (
        f"removing the Deny statement must restore the SAME assumed-role identity's access to "
        f"GetRoutingControlState; expected 'On', got {restored['RoutingControlState']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator
    accepting what AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _remove_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until_success(fn, timeout_s=90.0, interval_s=3.0):
    """Bounded retry for IAM policy-change propagation lag; raises (never returns a failure) on
    timeout so a target that never actually restores access cannot read as green."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"call did not succeed after {timeout_s}s: {last_err}")


def _assume_role_with_retry(sts, role_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-arc-deny-check"
            )["Credentials"]
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role after {timeout_s}s: {last_err}")


def _wait_cluster_deployed(cfg, cluster_arn, timeout_s=900.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfg.describe_cluster(ClusterArn=cluster_arn)["Cluster"]["Status"]
        if status == "DEPLOYED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached DEPLOYED (last status={status})")


def _wait_routing_control_deployed(cfg, rc_arn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfg.describe_routing_control(RoutingControlArn=rc_arn)["RoutingControl"]["Status"]
        if status == "DEPLOYED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"routing control never reached DEPLOYED (last status={status})")


_SHARED_CLUSTER_NAME = "sim2real-behav-r53arc-shared"


def _cluster_data_client(ctx, cfg, cluster_arn):
    """route53-recovery-cluster calls must target one of the cluster's 5 regional
    ClusterEndpoints -- there is no generic regional endpoint for this data plane."""
    endpoints = cfg.describe_cluster(ClusterArn=cluster_arn)["Cluster"]["ClusterEndpoints"]
    match = next((e for e in endpoints if e["Region"] == ctx.region), endpoints[0])
    return ctx.client("route53-recovery-cluster", endpoint_url=match["Endpoint"])


def _get_or_create_shared_cluster(ctx, cfg):
    """Reuse one ARC cluster across every check in this suite: real accounts are capped at
    2 concurrent clusters and a cluster takes several minutes to reach DEPLOYED, so each
    check provisioning (and tearing down) its own would blow both the per-check timeout and
    the account quota. Every check that uses it registers its teardown, and whichever finds it
    holding nothing else deletes it. Each check still creates and tears down
    its OWN routing control(s)/control panel/safety rule(s) inside it."""
    try:
        existing = [
            c
            for c in cfg.list_clusters().get("Clusters", [])
            if c.get("Name") == _SHARED_CLUSTER_NAME and c.get("Status") != "PENDING_DELETION"
        ]
    except ClientError:
        existing = []
    if existing:
        arn = existing[0]["ClusterArn"]
    else:
        try:
            arn = cfg.create_cluster(ClusterName=_SHARED_CLUSTER_NAME)["Cluster"]["ClusterArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ConflictException", "ValidationException"):
                raise
            existing = [
                c
                for c in cfg.list_clusters().get("Clusters", [])
                if c.get("Name") == _SHARED_CLUSTER_NAME and c.get("Status") != "PENDING_DELETION"
            ]
            if not existing:
                raise
            arn = existing[0]["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_shared_cluster(cfg, arn))
    _wait_cluster_deployed(cfg, arn, timeout_s=250.0, interval_s=5.0)
    panel_arn = cfg.list_control_panels(ClusterArn=arn)["ControlPanels"][0]["ControlPanelArn"]
    return arn, panel_arn


def _create_routing_control(ctx, cfg, cluster_arn, prefix="rc"):

    name = ctx.unique_name(f"sim2real-{prefix}-")
    arn = cfg.create_routing_control(ClusterArn=cluster_arn, RoutingControlName=name)[
        "RoutingControl"
    ]["RoutingControlArn"]

    def _cleanup():
        _delete_own(lambda: cfg.delete_routing_control(RoutingControlArn=arn))

    ctx.on_cleanup(_cleanup)
    _wait_routing_control_deployed(cfg, arn)
    return name, arn


def _wait_for_control_state(cluster, rc_arn, expected, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cluster.get_routing_control_state(RoutingControlArn=rc_arn)["RoutingControlState"]
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"routing control state never reached {expected!r} (last={last!r})")


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
