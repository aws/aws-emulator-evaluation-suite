"""resource-tag-condition-grants-get-secret-value-only-while-the-tag-matches."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-tag-condition-grants-get-secret-value-only-while-the-tag-matches"
GROUP = "enforcement"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-abac-reader"
_TAG_KEY = "sim2real-team"
_CREDENTIAL_PROPAGATION = frozenset(
    {"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"}
)


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity policy allowing GetSecretValue only under an aws:ResourceTag condition is
    evaluated against current tags: the role reads the tagged secret, is refused on an untagged one
    and after the tag is removed or changed, and reads again once the matching value is restored.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]
    team = ctx.unique_name("payments-")

    tagged = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-abac-tagged-"),
        SecretString="tagged-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": _TAG_KEY, "Value": team}],
    )
    tagged_arn = tagged["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=tagged_arn, ForceDeleteWithoutRecovery=True))

    untagged = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-abac-untagged-"),
        SecretString="untagged-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    untagged_arn = untagged["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=untagged_arn, ForceDeleteWithoutRecovery=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
                "Condition": {"StringEquals": {f"aws:ResourceTag/{_TAG_KEY}": team}},
            }
        ],
    }
    role_arn, role_name = _create_role(ctx, iam, account_id, policy)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"

    def denied(arn):
        return (
            "error",
            "AccessDeniedException",
            f"User: {session_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
            f"resource: {arn} because no identity-based policy allows the "
            "secretsmanager:GetSecretValue action",
        )

    # Positive: the matching tag grants the read (bounded wait for IAM/STS propagation).
    granted = _poll(
        lambda: _read(as_role, tagged_arn),
        lambda r: r[0] == "ok",
        timeout_s=90.0,
        interval_s=3.0,
        description="the tag-conditioned grant to become effective for the role",
    )
    assert granted == ("ok", "tagged-value"), f"the matching tag must grant the read; got {granted!r}"

    # Negative: same principal, same action, a secret without the tag.
    refused = _read(as_role, untagged_arn)
    assert refused == denied(untagged_arn), (
        f"a secret without the {_TAG_KEY} tag must be refused; got {refused!r}"
    )

    # Removing the tag revokes the grant.
    sm.untag_resource(SecretId=tagged_arn, TagKeys=[_TAG_KEY])
    after_untag = _poll(
        lambda: _read(as_role, tagged_arn),
        lambda r: r[0] == "error",
        timeout_s=60.0,
        interval_s=3.0,
        description="the untagged secret to stop matching the condition",
    )
    assert after_untag == denied(tagged_arn), (
        f"after UntagResource the role must be refused; got {after_untag!r}"
    )

    # A different value for the same key does not match either.
    sm.tag_resource(SecretId=tagged_arn, Tags=[{"Key": _TAG_KEY, "Value": team + "-other"}])
    stored = {t["Key"]: t["Value"] for t in sm.describe_secret(SecretId=tagged_arn).get("Tags", [])}
    assert stored.get(_TAG_KEY) == team + "-other", f"the retag must be stored; tags are {stored!r}"
    wrong_value = _read(as_role, tagged_arn)
    assert wrong_value == denied(tagged_arn), (
        f"a non-matching tag value must not satisfy StringEquals; got {wrong_value!r}"
    )

    # Restoring the matching value restores the read.
    sm.tag_resource(SecretId=tagged_arn, Tags=[{"Key": _TAG_KEY, "Value": team}])
    restored = _poll(
        lambda: _read(as_role, tagged_arn),
        lambda r: r[0] == "ok",
        timeout_s=60.0,
        interval_s=3.0,
        description="the restored tag to match the condition again",
    )
    assert restored == ("ok", "tagged-value"), f"the restored tag must grant the read; got {restored!r}"
    still_refused = _read(as_role, untagged_arn)
    assert still_refused == denied(untagged_arn), (
        f"the untagged control must still be refused; got {still_refused!r}"
    )


def _create_role(ctx, iam, account_id, policy):
    role_name = ctx.unique_name("sim2real-behav-abac-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="reader", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="reader"))
    return role["Role"]["Arn"], role_name


def _assume(sts, role_arn, timeout_s=60.0, interval_s=3.0):
    """Assume the freshly created role, retrying while its trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume-role never succeeded (trust policy propagation?): {last_err}")


def _client_as(ctx, creds):
    return ctx.client(
        "secretsmanager",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _read(client, secret_id):
    """("ok", value) on success, ("error", code, message) on a ClientError; a credential that is
    not yet recognized is reported as its own code so the caller can wait it out."""
    try:
        return ("ok", client.get_secret_value(SecretId=secret_id)["SecretString"])
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return ("error", error.get("Code"), error.get("Message"))


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) or (last[0] == "error" and last[1] in _CREDENTIAL_PROPAGATION):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
