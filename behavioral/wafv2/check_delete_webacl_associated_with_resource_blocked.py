"""delete-webacl-associated-with-resource-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-webacl-associated-with-resource-blocked"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a WebACL that is associated with a resource fails with
    WAFAssociatedItemException; disassociating first lets the delete succeed."""
    wafv2 = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool = cognito.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real": CHECK}
    )["UserPool"]
    pool_arn = pool["Arn"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))

    webacl_name = ctx.unique_name("sim2real-behav-webacl-")
    created = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config(webacl_name),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    webacl_arn = created["ARN"]
    webacl_id = created["Id"]
    lock_token = created["LockToken"]

    def _delete_webacl(token: str):
        return wafv2.delete_web_acl(
            Name=webacl_name, Scope="REGIONAL", Id=webacl_id, LockToken=token
        )

    ctx.on_cleanup(lambda: _best_effort_delete_webacl(wafv2, webacl_name, webacl_id))

    # A freshly created WebACL can take longer than a few seconds to fully propagate
    # (observed >60s on real AWS); until it does, AssociateWebACL raises
    # WAFUnavailableEntityException (documented behavior, not an error condition we're
    # testing here) -- retry through it with a generous bound.
    _retry_associate(wafv2, webacl_arn, pool_arn, timeout_s=240.0, interval_s=5.0)

    # Association propagation can lag a few seconds (documented eventual consistency).
    associated = _poll_until(
        lambda: wafv2.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL") is not None,
        lambda ok: ok is True,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert associated, "WebACL association with the Cognito user pool never became visible"

    code, message = _error(lambda: _delete_webacl(lock_token))
    assert code == "WAFAssociatedItemException", (
        f"expected DeleteWebACL on an associated WebACL to fail with "
        f"WAFAssociatedItemException, got {code!r}"
    )
    assert message == (
        "AWS WAF couldn’t perform the operation because your resource is being used by "
        "another resource or it’s associated with another resource."
    ), message

    # Effect absent: the WebACL must still exist, untouched.
    still_there = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    assert still_there["WebACL"]["Id"] == webacl_id, (
        f"expected the rejected delete to leave {webacl_id} in place, "
        f"got {still_there['WebACL'].get('Id')!r}"
    )
    current_lock_token = still_there["LockToken"]

    # Positive control: disassociate, then the delete succeeds (allow the same
    # propagation window for the disassociation to take effect).
    wafv2.disassociate_web_acl(ResourceArn=pool_arn)
    deadline = time.monotonic() + 30.0
    last_code = "WAFAssociatedItemException"
    while time.monotonic() < deadline and last_code == "WAFAssociatedItemException":
        try:
            _delete_webacl(current_lock_token)
            last_code = None
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            time.sleep(2.0)
    assert last_code is None, f"expected DeleteWebACL to succeed after disassociation, got {last_code}"

    code_after, message_after = _error(lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id))
    assert code_after == "WAFNonexistentItemException", (
        f"expected GetWebACL on the deleted {webacl_id} to fail with "
        f"WAFNonexistentItemException, got {code_after!r}"
    )
    assert message_after == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", message_after


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name.replace(".", ""),
    }


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_associate(wafv2, webacl_arn: str, resource_arn: str, *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            wafv2.associate_web_acl(WebACLArn=webacl_arn, ResourceArn=resource_arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "WAFUnavailableEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _best_effort_delete_webacl(wafv2, name: str, webacl_id: str) -> None:
    try:
        current = wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=webacl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise
        return
    try:
        wafv2.delete_web_acl(
            Name=name, Scope="REGIONAL", Id=webacl_id, LockToken=current["LockToken"]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
