"""policy-deletion-blocked-while-attached-to-app."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-deletion-blocked-while-attached-to-app"
GROUP = 'rejection'
SERVICES = ['resiliencehub']

_ERR_CONFLICT = 'ConflictException'
_ERR_NOT_FOUND = 'ResourceNotFoundException'


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DeleteResiliencyPolicy on a policy an app references is refused with ConflictException naming
    the app and both read back unchanged; after clearResiliencyPolicyArn the same delete succeeds
    and the policy answers ResourceNotFoundException.
    """
    rh = ctx.client("resiliencehub")

    policy_name = ctx.unique_name("sim2real-behav-rh-pol-")
    thresholds = {
        "Software": {"rtoInSecs": 600, "rpoInSecs": 300},
        "Hardware": {"rtoInSecs": 600, "rpoInSecs": 300},
        "AZ": {"rtoInSecs": 600, "rpoInSecs": 300},
    }
    policy_arn = rh.create_resiliency_policy(
        policyName=policy_name, tier="NonCritical", policy=thresholds
    )["policy"]["policyArn"]
    ctx.on_cleanup(lambda: _delete_policy_when_released(ctx, policy_arn))

    app_name = ctx.unique_name("sim2real-behav-rh-app-")
    app_arn = rh.create_app(name=app_name, policyArn=policy_arn)["app"]["appArn"]
    ctx.on_cleanup(lambda: rh.delete_app(appArn=app_arn, forceDelete=True))

    attached = rh.describe_app(appArn=app_arn)["app"]
    assert attached.get("policyArn") == policy_arn, (
        f"the app records policyArn {attached.get('policyArn')!r}, expected the policy this check "
        f"created ({policy_arn}) -- without the attachment there is nothing to block"
    )

    try:
        rh.delete_resiliency_policy(policyArn=policy_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        assert code == _ERR_CONFLICT, (
            f"deleting an attached policy failed with {code!r}, expected {_ERR_CONFLICT!r}. "
            f"message={message!r}"
        )
        expected = (
            f"Cannot delete policy {policy_name} ({policy_arn}). Policy currently associated with "
            f"app(s) {app_name} ({app_arn})"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"deleting policy {policy_arn} succeeded while app {app_name} still referenced it; "
            f"real AWS refuses with {_ERR_CONFLICT}"
        )

    survivor = rh.describe_resiliency_policy(policyArn=policy_arn)["policy"]
    assert survivor["policyArn"] == policy_arn, (
        f"after the refused delete the policy reads back as {survivor['policyArn']!r}, expected "
        f"{policy_arn} -- a refused delete must leave the resource intact"
    )
    assert survivor["policy"]["Software"]["rtoInSecs"] == 600, (
        f"the refused delete altered the policy: Software rtoInSecs is now "
        f"{survivor['policy']['Software']['rtoInSecs']}, expected 600"
    )
    still_attached = rh.describe_app(appArn=app_arn)["app"]
    assert still_attached.get("policyArn") == policy_arn, (
        f"after the refused delete the app records policyArn "
        f"{still_attached.get('policyArn')!r}, expected {policy_arn} unchanged"
    )

    # Positive control: detach, then the identical delete must go through.
    rh.update_app(appArn=app_arn, clearResiliencyPolicyArn=True)
    detached = rh.describe_app(appArn=app_arn)["app"]
    assert not detached.get("policyArn"), (
        f"clearResiliencyPolicyArn left the app pointing at {detached.get('policyArn')!r}; the "
        "detach did not take effect, so the delete below would not be a fair control"
    )

    deleted = rh.delete_resiliency_policy(policyArn=policy_arn)
    assert deleted["policyArn"] == policy_arn, (
        f"deleting the detached policy returned policyArn {deleted['policyArn']!r}, expected "
        f"{policy_arn} -- the earlier refusal was not about the attachment"
    )

    try:
        gone = rh.describe_resiliency_policy(policyArn=policy_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == _ERR_NOT_FOUND, (
            f"reading the deleted policy failed with {code!r}, expected {_ERR_NOT_FOUND!r}. "
            f"message={exc.response['Error']['Message']!r}"
        )
        expected = f"ResiliencyPolicy {policy_arn} not found"
        assert exc.response["Error"]["Message"] == expected, (
            f"expected message {expected!r}, got {exc.response['Error']['Message']!r}"
        )
    else:
        raise AssertionError(
            f"the policy still reads back after a successful delete: {gone['policy']['policyArn']}"
        )


def _delete_policy_when_released(ctx, policy_arn: str, timeout_s: float = 240.0,
                                interval_s: float = 8.0) -> None:
    """Teardown that waits out the app's reference to its resiliency policy.

    DeleteApp returns before that reference is released, so a policy delete issued straight after it
    is refused with ConflictException for up to a couple of minutes; the teardown retries that
    refusal. ResourceNotFoundException means the check's own body already deleted it.
    """
    rh = ctx.client("resiliencehub")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rh.delete_resiliency_policy(policyArn=policy_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
