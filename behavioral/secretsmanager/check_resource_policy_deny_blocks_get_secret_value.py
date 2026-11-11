"""resource-policy-deny-blocks-get-secret-value."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone.

    ForceDeleteWithoutRecovery because a secret in its recovery window still bills."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after "
                f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(Name=name, **kwargs)
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _drop_policy(sm, secret_id):
    """Best-effort policy removal; the secret's own cleanup is registered separately."""
    try:
        sm.delete_resource_policy(SecretId=secret_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


# What _outcome_of reports for a call that succeeded: a tuple no AWS error code can equal.
_SUCCEEDED = ("<call succeeded>", "<call succeeded>")


def _outcome_of(fn):
    """Call fn(); return (code, message) on ClientError, else the _SUCCEEDED sentinel."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _SUCCEEDED


def _poll(probe, predicate, *, timeout_s=90.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


def _digest(text):
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


CHECK = "resource-policy-deny-blocks-get-secret-value"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit resource-policy Deny blocks GetSecretValue, only that action, and reversibly.

    The same read succeeds before the policy is attached and after it is deleted, so the denial
    is Secrets Manager's own policy evaluation rather than a caller-permission 403.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-rpdeny-")

    value = "sim2real-not-a-real-secret"
    created = _create_secret(sm, ctx, name, SecretString=value)
    arn = created["ARN"]
    v1 = created["VersionId"]
    # Registered after the secret's cleanup so LIFO cleanup drops the policy first.
    ctx.on_cleanup(lambda: _drop_policy(sm, arn))

    # Control BEFORE: the read works with these credentials and this secret.
    before = sm.get_secret_value(SecretId=arn)
    assert before["ARN"] == arn, f"read resolved a different secret: {before['ARN']} != {arn}"
    assert before["VersionId"] == v1, (
        f"positive control returned version {before['VersionId']!r}, expected {v1!r}"
    )
    assert _digest(before["SecretString"]) == _digest(value), (
        f"positive control read back sha256 {_digest(before['SecretString'])}, "
        f"expected {_digest(value)}"
    )

    deny = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realDenyRead",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": arn,
            }
        ],
    }
    # The wildcard principal is on a Deny, which is not broad access.
    sm.put_resource_policy(
        SecretId=arn, ResourcePolicy=json.dumps(deny), BlockPublicPolicy=False
    )

    # The document must be readable back, and it must be the Deny we attached.
    stored = json.loads(sm.get_resource_policy(SecretId=arn)["ResourcePolicy"])
    assert stored["Statement"][0]["Effect"] == "Deny", (
        f"the attached statement must be a Deny, got {stored['Statement'][0]}"
    )

    # Policy evaluation is eventually consistent; bound the wait rather than sleeping.
    code, message = _poll(
        lambda: _outcome_of(lambda: sm.get_secret_value(SecretId=arn)),
        lambda got: got[0] == "AccessDeniedException",
    )
    assert code == "AccessDeniedException", (
        "an explicit Deny on secretsmanager:GetSecretValue must block the read that "
        f"succeeded moments earlier; got code={code!r} message={message!r}. A "
        f"{_SUCCEEDED[0]!r} code means the policy was stored but never evaluated."
    )
    # The message names the resource-based policy, so the denial is attributable to it rather
    # than to an ambient identity-policy 403.
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f"User: {caller} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {arn} with an explicit deny in a resource-based policy"
    )
    assert message == expected, f"denial message was {message!r}, expected {expected!r}"

    # The Deny is SCOPED: metadata reads on the same secret still succeed.
    desc = sm.describe_secret(SecretId=arn)
    assert desc["ARN"] == arn, "DescribeSecret is not denied and must still resolve"
    assert set(desc["VersionIdsToStages"][v1]) == {"AWSCURRENT"}, (
        f"the denial must not disturb the staging map, got {desc['VersionIdsToStages']}"
    )

    # Reversible: removing the policy restores the read, byte-identically.
    sm.delete_resource_policy(SecretId=arn)
    after_code = _poll(
        lambda: _outcome_of(lambda: sm.get_secret_value(SecretId=arn))[0],
        lambda got: got == _SUCCEEDED[0],
    )
    assert after_code == _SUCCEEDED[0], (
        "deleting the resource policy must restore GetSecretValue; still failing with "
        f"{after_code}"
    )
    after = sm.get_secret_value(SecretId=arn)
    assert after["VersionId"] == v1, (
        f"restored read returned version {after['VersionId']!r}, expected {v1!r}"
    )
    assert _digest(after["SecretString"]) == _digest(value), (
        "the secret material must be byte-identical after the deny/allow cycle; "
        f"sha256 {_digest(after['SecretString'])} != {_digest(value)}"
    )
    assert not sm.get_resource_policy(SecretId=arn).get("ResourcePolicy"), (
        "GetResourcePolicy must report no policy once it has been deleted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
