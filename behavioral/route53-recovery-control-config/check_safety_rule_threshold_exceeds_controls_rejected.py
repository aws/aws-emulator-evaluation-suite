"""safety-rule-threshold-exceeds-controls-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "safety-rule-threshold-exceeds-controls-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """CreateSafetyRule accepts an ATLEAST Threshold of 3 over 2 AssertedControls; the
    unsatisfiable rule then blocks every UpdateRoutingControlState on those controls with
    a ValidationException naming it, and deleting the rule restores the same transition."""
    client = ctx.client("route53-recovery-control-config")

    cluster_arn = _get_or_create_shared_cluster(ctx, client)
    cluster = client.describe_cluster(ClusterArn=cluster_arn)["Cluster"]
    endpoints = cluster["ClusterEndpoints"]
    ep = next((e for e in endpoints if e["Region"] == ctx.region), endpoints[0])
    ep_url = ctx.endpoint_url(ep["Endpoint"])
    cluster_client = ctx.client("route53-recovery-cluster", endpoint_url=ep_url, region=ep["Region"])

    panel_arn = client.create_control_panel(
        ClusterArn=cluster_arn, ControlPanelName=ctx.unique_name("sim2real-r53arc-panel-")
    )["ControlPanel"]["ControlPanelArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_control_panel(ControlPanelArn=panel_arn)))
    _wait_deployed(lambda: client.describe_control_panel(ControlPanelArn=panel_arn)["ControlPanel"])

    def make_rc(i):
        arn = client.create_routing_control(
            ClusterArn=cluster_arn,
            ControlPanelArn=panel_arn,
            RoutingControlName=ctx.unique_name(f"sim2real-r53arc-rc{i}-"),
        )["RoutingControl"]["RoutingControlArn"]
        ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_routing_control(RoutingControlArn=arn)))
        _wait_deployed(lambda: client.describe_routing_control(RoutingControlArn=arn)["RoutingControl"])
        return arn

    rc0 = make_rc(0)
    rc1 = make_rc(1)
    asserted_controls = [rc0, rc1]

    # positive control: with no safety rule yet, the data plane genuinely toggles state
    initial_state = cluster_client.get_routing_control_state(RoutingControlArn=rc0)["RoutingControlState"]
    flipped = "Off" if initial_state == "On" else "On"
    cluster_client.update_routing_control_state(RoutingControlArn=rc0, RoutingControlState=flipped)
    state = _poll_state(cluster_client, rc0, flipped)
    assert state == flipped, state
    cluster_client.update_routing_control_state(RoutingControlArn=rc0, RoutingControlState=initial_state)
    state = _poll_state(cluster_client, rc0, initial_state)
    assert state == initial_state, state

    # break: an ATLEAST rule that only 2 controls can never satisfy (needs >= 3 On)
    rule_arn = client.create_safety_rule(
        AssertionRule={
            "Name": ctx.unique_name("sim2real-r53arc-badthresh-"),
            "ControlPanelArn": panel_arn,
            "AssertedControls": asserted_controls,
            "RuleConfig": {"Type": "ATLEAST", "Threshold": 3, "Inverted": False},
            "WaitPeriodMs": 0,
        },
    )["AssertionRule"]["SafetyRuleArn"]
    ctx.on_cleanup(lambda: _delete_own(lambda: client.delete_safety_rule(SafetyRuleArn=rule_arn)))
    _wait_deployed(lambda: client.describe_safety_rule(SafetyRuleArn=rule_arn)["AssertionRule"])

    # negative: blocked by THIS specific rule, not just any ValidationException
    target_state = "Off" if initial_state == "On" else "On"
    code, message = _error(
        lambda: cluster_client.update_routing_control_state(
            RoutingControlArn=rc0, RoutingControlState=target_state
        )
    )
    assert code == "ValidationException", code
    expected_message = (
        "Can't update the routing control state because of a configured safety rule: "
        '"At least 3 routing controls must be On." To override the rule and change the state, '
        "see the guidance for AllowSafetyRulesOverride in the Route 53 ARC Developer Guide. "
        f"\nRouting control: [{rc0}] \nSafety rule: {rule_arn}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect absent: the state did not move
    state = cluster_client.get_routing_control_state(RoutingControlArn=rc0)["RoutingControlState"]
    assert state == initial_state, state

    # restore: remove the unsatisfiable rule
    client.delete_safety_rule(SafetyRuleArn=rule_arn)
    _wait_rule_gone(client, panel_arn, rule_arn)

    # identical call now succeeds
    cluster_client.update_routing_control_state(RoutingControlArn=rc0, RoutingControlState=target_state)
    state = _poll_state(cluster_client, rc0, target_state)
    assert state == target_state, state


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
    except ClientError:
        pass


def _wait_deployed(probe, timeout_s=180.0, interval_s=5.0):
    import time

    deadline = time.monotonic() + timeout_s
    resource = None
    while time.monotonic() < deadline:
        resource = probe()
        if resource["Status"] == "DEPLOYED":
            return resource
        time.sleep(interval_s)
    raise AssertionError(f"resource did not reach DEPLOYED in time (last: {resource!r})")


def _wait_rule_gone(client, panel_arn, rule_arn, timeout_s=90.0, interval_s=5.0):
    import time

    deadline = time.monotonic() + timeout_s
    rules = None
    while time.monotonic() < deadline:
        rules = client.list_safety_rules(ControlPanelArn=panel_arn)["SafetyRules"]
        arns = [
            (r.get("ASSERTION") or r.get("GATING") or {}).get("SafetyRuleArn") for r in rules
        ]
        if rule_arn not in arns:
            return
        time.sleep(interval_s)
    raise AssertionError(f"safety rule did not disappear in time (last: {rules!r})")


def _poll_state(cluster_client, rc_arn, expected, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = cluster_client.get_routing_control_state(RoutingControlArn=rc_arn)[
            "RoutingControlState"
        ]
        if state == expected:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"routing control did not reach {expected!r} in time (last: {state!r})")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError but call succeeded: {result!r}")


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
