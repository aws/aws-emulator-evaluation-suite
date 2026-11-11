"""delete-ipset-referenced-by-webacl-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-ipset-referenced-by-webacl-rejected"
GROUP = "server-side"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIPSet on an IPSet that a WebACL rule still references is rejected with
    WAFAssociatedItemException, the IPSet is not removed, and once the referencing
    WebACL is deleted the very same DeleteIPSet call succeeds.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    ip_set_name = ctx.unique_name("sim2real-behav-inuse-ipset-")
    web_acl_name = ctx.unique_name("sim2real-behav-inuse-webacl-")
    metric_name = web_acl_name.replace("-", "")

    ip_set = wafv2.create_ip_set(
        Name=ip_set_name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=["10.0.0.1/32"],
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ip_set_id = ip_set["Summary"]["Id"]
    ip_set_arn = ip_set["Summary"]["ARN"]

    def _make_web_acl():
        return wafv2.create_web_acl(
            Name=web_acl_name,
            Scope=scope,
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "block-via-ipset",
                    "Priority": 0,
                    "Action": {"Block": {}},
                    "Statement": {"IPSetReferenceStatement": {"ARN": ip_set_arn}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": f"{metric_name}rule",
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": metric_name,
            },
            Tags=[{"Key": "sim2real:check", "Value": CHECK}],
        )

    # A just-created IPSet can briefly be unavailable for reference from a new
    # WebACL (WAFUnavailableEntityException) due to control-plane propagation
    # lag; poll with a bounded retry rather than a single attempt.
    web_acl = None
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            web_acl = _make_web_acl()
            break
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
            if code != "WAFUnavailableEntityException":
                raise
            last_err = exc
            time.sleep(3)
    if web_acl is None:
        raise AssertionError(
            f"CreateWebACL kept failing with WAFUnavailableEntityException referencing "
            f"the just-created IPSet within 60s: {last_err!r}"
        )
    web_acl_id = web_acl["Summary"]["Id"]


    def _cleanup() -> None:
        try:
            wafv2.delete_web_acl(
                Name=web_acl_name,
                Scope=scope,
                Id=web_acl_id,
                LockToken=wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)["LockToken"],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
        try:
            wafv2.delete_ip_set(
                Name=ip_set_name,
                Scope=scope,
                Id=ip_set_id,
                LockToken=wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)["LockToken"],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    ip_set_lock_token = wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)["LockToken"]
    code, message = _error(
        lambda: wafv2.delete_ip_set(
            Name=ip_set_name, Scope=scope, Id=ip_set_id, LockToken=ip_set_lock_token
        )
    )
    assert code == "WAFAssociatedItemException", f"expected WAFAssociatedItemException, got {code!r}"
    assert message == (
        "AWS WAF couldn’t perform the operation because your resource is being used by "
        "another resource or it’s associated with another resource."
    ), message

    # The effect of the rejected delete must be absent: the IPSet still exists.
    still_there = wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
    assert still_there["IPSet"]["Id"] == ip_set_id, (
        f"expected rejected DeleteIPSet to leave {ip_set_id!r} in place, "
        f"got IPSet Id {still_there['IPSet']['Id']!r}"
    )

    # Positive control: once the referencing WebACL is gone, the same delete succeeds.
    wafv2.delete_web_acl(
        Name=web_acl_name,
        Scope=scope,
        Id=web_acl_id,
        LockToken=wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)["LockToken"],
    )
    wafv2.delete_ip_set(
        Name=ip_set_name,
        Scope=scope,
        Id=ip_set_id,
        LockToken=wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)["LockToken"],
    )
    code_after, message_after = _error(lambda: wafv2.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id))
    assert code_after == "WAFNonexistentItemException", (
        f"expected GetIPSet on the deleted {ip_set_id!r} to fail with "
        f"WAFNonexistentItemException, got {code_after!r}"
    )
    assert message_after == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", message_after


def _error(fn) -> tuple[str, str]:
    """Return (code, message) of the ClientError fn raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
