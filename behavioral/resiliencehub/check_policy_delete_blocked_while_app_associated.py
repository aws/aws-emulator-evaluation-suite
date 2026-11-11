"""policy-delete-blocked-while-app-associated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-delete-blocked-while-app-associated"
GROUP = 'resiliency-policies'
SERVICES = ['resiliencehub']


class _UnexpectedSuccess(Exception):
    """A call real AWS rejects returned successfully."""


def _error_code(fn, seen=None):
    """Call fn(); return the Error.Code of the ClientError it must raise.

    An unexpected success raises rather than returning a falsy sentinel: an emulator accepting
    input real AWS rejects is the strongest signal available and must not read as a code mismatch.
    When `seen` is a dict it receives the whole Error entry, so the message can be asserted
    without firing the call twice.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if seen is not None:
            seen.update(err)
        return err.get("Code")
    raise _UnexpectedSuccess(f"expected a rejection, got a successful response: {result!r}")


def _gone(fn, *codes):
    """Run a teardown step, tolerating only the codes that mean it is already done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _await_app_deleted(rh, app_arn, deadline=180.0):
    """DeleteApp is asynchronous — the app answers 200 with status Deleting first."""
    last, end = None, time.time() + deadline
    while time.time() < end:
        try:
            last = rh.describe_app(appArn=app_arn)["app"]["status"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(
        f"app {app_arn!r} was still {last!r} {deadline}s after DeleteApp")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResiliencyPolicy on a policy an app names is refused with ConflictException naming the
    app and both read back unchanged; once the app is deleted the same call succeeds and the policy
    then answers ResourceNotFoundException.
    """
    rh = ctx.client("resiliencehub")

    policy_name = ctx.unique_name("sim2real-behav-rh-inuse-pol-")
    targets = {d: {"rtoInSecs": 60, "rpoInSecs": 86400}
               for d in ("AZ", "Hardware", "Software", "Region")}
    policy_arn = rh.create_resiliency_policy(
        policyName=policy_name, tier="CoreServices", policy=targets)["policy"]["policyArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_resiliency_policy(policyArn=policy_arn), "ResourceNotFoundException"))

    app_name = ctx.unique_name("sim2real-behav-rh-inuse-")
    app_arn = rh.create_app(name=app_name, policyArn=policy_arn)["app"]["appArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_app(appArn=app_arn, forceDelete=True), "ResourceNotFoundException"))

    associated = rh.describe_app(appArn=app_arn)["app"]
    assert associated["policyArn"] == policy_arn, (
        f"app names policyArn {associated.get('policyArn')!r}, expected {policy_arn!r}")

    # The one broken thing: the policy is still referenced.
    err = {}
    code = _error_code(lambda: rh.delete_resiliency_policy(policyArn=policy_arn), err)
    assert code == "ConflictException", (
        f"deleting a policy an app names returned {code!r}, expected ConflictException "
        f"({err.get('Message')!r})")
    in_use_message = (
        f"Cannot delete policy {policy_name} ({policy_arn}). "
        f"Policy currently associated with app(s) {app_name} ({app_arn})")
    assert err.get("Message") == in_use_message, (
        f"the refusal returned message {err.get('Message')!r}, expected {in_use_message!r}")

    survived = rh.describe_resiliency_policy(policyArn=policy_arn)["policy"]
    assert survived["policyArn"] == policy_arn, (
        f"policy came back as {survived.get('policyArn')!r} after the refused delete")
    assert survived["policyName"] == policy_name, (
        f"policy is named {survived['policyName']!r} after the refused delete, "
        f"expected {policy_name!r}")
    assert survived["policy"]["AZ"]["rtoInSecs"] == targets["AZ"]["rtoInSecs"], (
        f"the refused delete changed the AZ target to {survived['policy']['AZ']!r}, "
        f"expected {targets['AZ']!r}")
    assert rh.describe_app(appArn=app_arn)["app"]["policyArn"] == policy_arn, (
        "the refused delete dropped the association it was refused for")

    # Positive control: remove the association, and the same delete is accepted.
    rh.delete_app(appArn=app_arn, forceDelete=True)
    _await_app_deleted(rh, app_arn)
    rh.delete_resiliency_policy(policyArn=policy_arn)
    gone = {}
    code = _error_code(lambda: rh.describe_resiliency_policy(policyArn=policy_arn), gone)
    assert code == "ResourceNotFoundException", (
        f"the deleted policy still resolves: describe returned {code!r} "
        f"({gone.get('Message')!r})")
    assert gone.get("Message") == f"ResiliencyPolicy {policy_arn} not found", (
        f"describe of the deleted policy returned message {gone.get('Message')!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
