"""create-launch-configuration-template-access-denied-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-launch-configuration-template-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


def _poll(probe, predicate, *, timeout_s, interval_s, description, detail=None):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            extra = f"; detail={detail()!r}" if detail else ""
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}{extra}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity with no mgn:* grant gets AccessDeniedException from CreateLaunchConfigurationTemplate
    and creates nothing; once granted mgn:*, its outcome equals the authorized caller's baseline, so
    IAM authorization is enforced ahead of account-level business state.
    """
    mgn = ctx.client("mgn")
    iam = ctx.client("iam")

    created_ids = []
    last_error = {}

    def _call(client):
        try:
            resp = client.create_launch_configuration_template(tags={"sim2real": CHECK})
            created_ids.append(resp["launchConfigurationTemplateID"])
            return "UNEXPECTED_SUCCESS"
        except ClientError as e:
            last_error["error"] = e.response.get("Error", {})
            return e.response["Error"]["Code"]

    def _delete_created():
        while created_ids:
            mgn.delete_launch_configuration_template(
                launchConfigurationTemplateID=created_ids.pop()
            )

    def _list_snapshot():
        """(code, ids) from an independent read (Describe, never Create). ``code`` is "OK" on
        success -- some accounts refuse even this read with the same business exception the
        baseline observed, and that refusal itself must not change across the denied attempts."""
        try:
            paginator = mgn.get_paginator("describe_launch_configuration_templates")
            ids = frozenset(
                item["launchConfigurationTemplateID"]
                for page in paginator.paginate()
                for item in page.get("items", [])
            )
            return ("OK", ids)
        except ClientError as e:
            return (e.response["Error"]["Code"], frozenset())

    # --- Baseline: the account's own authorized caller establishes the real business-state
    # outcome for this call, whatever it is in this account. This must not itself be an IAM
    # rejection, or there is no business-state baseline to contrast the denial against.
    baseline_code = _call(mgn)
    assert baseline_code != "AccessDeniedException", (
        "the harness's own authorized mgn client must not itself be denied by IAM -- cannot "
        "establish a business-state baseline to contrast the unauthorized identity against"
    )
    _delete_created()

    user_name = ctx.unique_name("sim2real-mgn-noperm-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    unpriv_mgn = ctx.client(
        "mgn",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    # --- The unauthorized identity: IAM credential propagation can lag by a few seconds; poll
    # for the expected rejection.
    snapshot_before_denial = _list_snapshot()
    seen_code = _poll(
        lambda: _call(unpriv_mgn),
        lambda c: c == "AccessDeniedException",
        timeout_s=45.0,
        interval_s=3.0,
        description="an unauthorized identity being rejected by IAM",
    )
    assert seen_code == "AccessDeniedException", (
        f"expected AccessDeniedException for an unauthorized identity, got {seen_code!r} "
        "(IAM authorization must be enforced ahead of any account-level business state)"
    )
    partition = user_arn.split(":")[1]
    denied_message = (
        f"User: {user_arn} is not authorized to perform: mgn:CreateLaunchConfigurationTemplate "
        f"on resource: arn:{partition}:mgn:{ctx.region}:{ctx.account}:launch-configuration-template/* "
        f"because no identity-based policy allows the mgn:CreateLaunchConfigurationTemplate action"
    )
    assert last_error["error"].get("Message") == denied_message, (
        f"expected AccessDeniedException message {denied_message!r}, got "
        f"{last_error['error'].get('Message')!r}"
    )
    assert not created_ids, "an unauthorized identity must never be able to create a template"
    # Independent read at the destination, through DescribeLaunchConfigurationTemplates rather
    # than the Create call's own response: the rejected attempts left no trace, whether that
    # read reports a real (empty-diff) template list or refuses with the account's own business
    # exception.
    snapshot_after_denial = _list_snapshot()
    assert snapshot_after_denial == snapshot_before_denial, (
        "an unauthorized identity's rejected calls must leave the account's launch configuration "
        f"template list unchanged; before={snapshot_before_denial} after={snapshot_after_denial}"
    )

    # --- Restore: grant the identity the mgn:* access it lacked. Its outcome must collapse onto
    # the baseline -- the same business-state result the authorized caller saw -- not stay pinned
    # to AccessDeniedException.
    policy_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-mgn-noperm-allow-"),
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "mgn:*", "Resource": "*"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))
    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn))

    restored_code = _poll(
        lambda: _call(unpriv_mgn),
        lambda c: c == baseline_code,
        timeout_s=180.0,
        interval_s=3.0,
        description="the granted mgn:* policy collapsing the identity's outcome onto the baseline",
        detail=lambda: last_error.get("error"),
    )
    assert restored_code == baseline_code, (
        f"granting mgn:* must restore the same business-state outcome an authorized caller sees "
        f"({baseline_code!r}), not leave the identity pinned to an IAM rejection; got "
        f"{restored_code!r} ({last_error.get('error')!r})"
    )
    _delete_created()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
