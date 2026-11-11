"""resource-policy-put-get-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-delete-lifecycle"
GROUP = "resource-policy"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a core network refuses a well-formed Allow policy with ValidationException
    "Invalid policy." and attaches nothing; GetResourcePolicy before and after it, and after
    DeleteResourcePolicy on the absent policy, reports no policy."""
    nm = ctx.client("networkmanager")

    gn_id = _create_global_network(ctx, nm)
    cn = nm.create_core_network(
        GlobalNetworkId=gn_id,
        Description=ctx.unique_name("sim2real-cn-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CoreNetwork"]
    cn_id = cn["CoreNetworkId"]
    cn_arn = cn["CoreNetworkArn"]
    ctx.on_cleanup(lambda: _delete_core_network_and_wait(nm, cn_id))
    _poll_until(
        lambda: nm.get_core_network(CoreNetworkId=cn_id)["CoreNetwork"]["State"],
        lambda s: s == "AVAILABLE",
    )

    # Positive control: the core network is otherwise fully usable -- GetResourcePolicy against a
    # never-attached policy succeeds and reports none, so the coming refusal is not a broken
    # account or a broken core network.
    baseline = nm.get_resource_policy(ResourceArn=cn_arn).get("PolicyDocument")
    assert not baseline, f"expected no resource policy before any PutResourcePolicy attempt, got {baseline!r}"

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "networkmanager:GetCoreNetwork"}],
        }
    )
    try:
        nm.put_resource_policy(ResourceArn=cn_arn, PolicyDocument=policy)
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ValidationException", (
            f"expected PutResourcePolicy to be refused with ValidationException, got {error['Code']!r}"
        )
        expected_message = "Invalid policy."
        assert error.get("Message") == expected_message, (
            f"expected message {expected_message!r}, got {error.get('Message')!r}"
        )
    else:
        raise AssertionError(
            "PutResourcePolicy on a core network unexpectedly SUCCEEDED in this account -- the "
            "deterministic refusal this check pins is no longer reproduced; re-audit before trusting "
            "this result"
        )

    # Effect-absent: the refused PutResourcePolicy left no policy attached.
    after_attempt = nm.get_resource_policy(ResourceArn=cn_arn).get("PolicyDocument")
    assert not after_attempt, f"expected no resource policy after the refused PutResourcePolicy, got {after_attempt!r}"

    # DeleteResourcePolicy against a core network with no attached policy is itself well-defined:
    # it is a no-op, and a subsequent read still reports no policy.
    nm.delete_resource_policy(ResourceArn=cn_arn)
    after_delete = nm.get_resource_policy(ResourceArn=cn_arn).get("PolicyDocument")
    assert not after_delete, f"expected no resource policy after DeleteResourcePolicy on an absent policy, got {after_delete!r}"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _is_gone(fn):
    """True once fn() is refused with ResourceNotFoundException or answers an empty list (polling only)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"
    return result == []


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_global_network(ctx, nm):
    gn_id = nm.create_global_network(
        Description=ctx.unique_name("sim2real-gn-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["GlobalNetwork"]["GlobalNetworkId"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id


def _delete_core_network_and_wait(nm, cn_id):
    _safe_call(lambda: nm.delete_core_network(CoreNetworkId=cn_id))
    _poll_until(
        lambda: _is_gone(lambda: nm.get_core_network(CoreNetworkId=cn_id)),
        lambda gone: gone,
        timeout_s=180.0,
    )


def _delete_global_network_and_wait(nm, gn_id):
    _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    _poll_until(
        lambda: _is_gone(lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]),
        lambda gone: gone,
        timeout_s=180.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
