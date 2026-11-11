"""webacl-delete-blocked-while-associated-to-resource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-delete-blocked-while-associated-to-resource"
GROUP = "state-machine"
SERVICES = ["wafv2"]

_ASSOCIATED_MESSAGE = (
    "AWS WAF couldn\u2019t perform the operation because your resource is being used by "
    "another resource or it\u2019s associated with another resource."
)
_NONEXISTENT_MESSAGE = (
    "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWebACL is rejected with WAFAssociatedItemException while the WebACL is
    associated with a resource (a Cognito user pool); the association is not affected
    by the failed delete, and once disassociated the same delete succeeds."""
    wafv2 = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")

    web_acl_name = ctx.unique_name("sim2real-behav-wacl-")
    summary = wafv2.create_web_acl(
        Name=web_acl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": web_acl_name,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    web_acl_arn = summary["ARN"]
    web_acl_id = summary["Id"]
    ctx.on_cleanup(
        lambda: _force_delete_web_acl(wafv2, web_acl_name, "REGIONAL", web_acl_id, web_acl_arn)
    )

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool = cognito.create_user_pool(PoolName=pool_name, UserPoolTags={"sim2real": CHECK})["UserPool"]
    pool_arn = pool["Arn"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: cognito.delete_user_pool(UserPoolId=pool_id)))

    _associate_with_retry(wafv2, web_acl_arn, pool_arn)
    ctx.on_cleanup(lambda: _safe_call(lambda: wafv2.disassociate_web_acl(ResourceArn=pool_arn)))
    # AssociateWebACL can return success before the association is visible to other calls
    # (documented eventual consistency); without waiting for GetWebACLForResource to reflect it,
    # DeleteWebACL could race ahead of the block taking effect and this check would flake.
    _wait_association(wafv2, pool_arn, web_acl_arn, present=True)

    lock_token = wafv2.get_web_acl(Name=web_acl_name, Scope="REGIONAL", Id=web_acl_id)["LockToken"]
    error = _error(
        lambda: wafv2.delete_web_acl(
            Name=web_acl_name, Scope="REGIONAL", Id=web_acl_id, LockToken=lock_token
        )
    )
    assert error.get("Code") == "WAFAssociatedItemException", (
        f"expected WAFAssociatedItemException, got {error}"
    )
    assert error.get("Message") == _ASSOCIATED_MESSAGE, f"unexpected message: {error}"

    # the rejected delete must not have removed the web ACL
    wafv2.get_web_acl(Name=web_acl_name, Scope="REGIONAL", Id=web_acl_id)

    # positive control: once disassociated, the identical delete succeeds
    wafv2.disassociate_web_acl(ResourceArn=pool_arn)
    _wait_association(wafv2, pool_arn, web_acl_arn, present=False)
    lock_token = wafv2.get_web_acl(Name=web_acl_name, Scope="REGIONAL", Id=web_acl_id)["LockToken"]
    wafv2.delete_web_acl(Name=web_acl_name, Scope="REGIONAL", Id=web_acl_id, LockToken=lock_token)
    gone = _error(lambda: wafv2.get_web_acl(Name=web_acl_name, Scope="REGIONAL", Id=web_acl_id))
    assert gone.get("Code") == "WAFNonexistentItemException", f"expected WAFNonexistentItemException, got {gone}"
    assert gone.get("Message") == _NONEXISTENT_MESSAGE, f"unexpected message: {gone}"


def _error(fn):
    """The AWS ``Error`` (code and message) for a call that MUST fail.

    Raises rather than returning a falsy sentinel.
    """
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "WAFNonexistentItemException",
        ):
            raise


def _wait_association(wafv2, resource_arn, web_acl_arn, *, present, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = "<unread>"
    while time.monotonic() < deadline:
        current = wafv2.get_web_acl_for_resource(ResourceArn=resource_arn).get("WebACL")
        last = current.get("ARN") if current else None
        if present and last == web_acl_arn:
            return
        if not present and current is None:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"GetWebACLForResource never reflected present={present} for {resource_arn}; last observed {last!r}"
    )


def _associate_with_retry(wafv2, web_acl_arn, resource_arn, timeout_s=180.0):
    # A freshly created web ACL can briefly be WAFUnavailableEntityException while
    # it propagates before it can be associated with a resource.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            wafv2.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=resource_arn)
            return
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "WAFUnavailableEntityException":
                raise
            time.sleep(3)
    raise AssertionError(f"AssociateWebACL never succeeded: {last_err}")


def _force_delete_web_acl(wafv2, name, scope, web_acl_id, arn):
    try:
        resources = wafv2.list_resources_for_web_acl(WebACLArn=arn).get("ResourceArns", [])
        for resource_arn in resources:
            _safe_call(lambda r=resource_arn: wafv2.disassociate_web_acl(ResourceArn=r))
        lock_token = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"]
        wafv2.delete_web_acl(Name=name, Scope=scope, Id=web_acl_id, LockToken=lock_token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
