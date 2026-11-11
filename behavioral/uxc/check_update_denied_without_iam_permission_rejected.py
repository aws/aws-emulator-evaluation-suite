"""update-denied-without-iam-permission-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError, EndpointConnectionError

from behavioral_harness import tags

CHECK = "update-denied-without-iam-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["uxc"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """An IAM identity with no attached permissions is denied UpdateAccountCustomizations with AccessDeniedException, the setting stays at its previous value, and the same call from a privileged identity still succeeds."""
    uxc = ctx.client("uxc")
    iam = ctx.client("iam")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    baseline_color = "yellow"
    uxc.update_account_customizations(accountColor=baseline_color)
    got_baseline = uxc.get_account_customizations()["accountColor"]
    assert got_baseline == baseline_color, f"expected baseline {baseline_color!r}, got {got_baseline!r}"

    user_name = ctx.unique_name("sim2real-uxc-denied-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id, secret_access_key = key["AccessKeyId"], key["SecretAccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))

    unpriv_client = ctx.client(
        "uxc",
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )

    code, message = _wait_for_denied(
        lambda: unpriv_client.update_account_customizations(accountColor="teal"),
        timeout_s=45.0,
        interval_s=3.0,
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"uxc:UpdateAccountCustomizations on resource: "
        f"arn:aws:uxc::{ctx.account}:account-customizations because no identity-based policy "
        f"allows the uxc:UpdateAccountCustomizations action"
    )
    assert message == expected_message, f"unexpected message={message!r}"

    # Effect absent: the unauthorized call must not have changed the persisted color.
    got_after_denial = uxc.get_account_customizations()["accountColor"]
    assert got_after_denial == baseline_color, (
        f"denied update must not change accountColor: expected {baseline_color!r}, got {got_after_denial!r}"
    )

    # Positive control: the same change from a privileged identity still succeeds.
    resp = uxc.update_account_customizations(accountColor="teal")
    assert resp["accountColor"] == "teal", f"expected accountColor 'teal' in response, got {resp['accountColor']!r}"
    got_final = uxc.get_account_customizations()["accountColor"]
    assert got_final == "teal", f"expected persisted accountColor 'teal', got {got_final!r}"


def _wait_for_denied(fn, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_code = "Success"
    while time.monotonic() < deadline:
        try:
            fn()
            last_code = "Success"
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "AccessDeniedException":
                return code, err.response["Error"].get("Message")
            last_code = code
        except EndpointConnectionError as err:
            # A transient connect blip; bounded retry, never treated as the denial.
            last_code = f"EndpointConnectionError:{err}"
        time.sleep(interval_s)
    raise AssertionError(
        f"never observed AccessDeniedException within {timeout_s}s; last observed={last_code!r}"
    )


def _snapshot(uxc):
    resp = uxc.get_account_customizations()
    return {
        "accountColor": resp.get("accountColor", "none"),
        "visibleServices": resp.get("visibleServices"),
        "visibleRegions": resp.get("visibleRegions"),
    }


def _restore(uxc, snap):
    kwargs = {"accountColor": snap["accountColor"] or "none"}
    if snap["visibleServices"] is not None:
        kwargs["visibleServices"] = snap["visibleServices"]
    if snap["visibleRegions"] is not None:
        kwargs["visibleRegions"] = snap["visibleRegions"]
    uxc.update_account_customizations(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
