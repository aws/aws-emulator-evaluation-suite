"""deactivated-access-key-is-refused-by-sts-kms-and-secrets-manager."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deactivated-access-key-is-refused-by-sts-kms-and-secrets-manager"
GROUP = "access_keys"
SERVICES = ["iam", "kms", "secretsmanager", "sts"]

_POLICY_NAME = "sim2real-behav-keystate-reads"
_MARK = [{"Key": "sim2real", "Value": CHECK}]
_OK = "OK"

#: A query-protocol service (STS) refuses an inactive access key with this pair.
_STS_REFUSED = ("InvalidClientTokenId", "The security token included in the request is invalid.")
#: A JSON-protocol service (KMS, Secrets Manager) refuses it with this pair.
_JSON_REFUSED = (
    "UnrecognizedClientException",
    "The security token included in the request is invalid.",
)

#: Bound on a deactivation reaching other services' signers; it fits a short run budget
#: so a key that is never refused fails rather than running the budget out.
_REVOCATION_S = 45.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An access key deactivated before its first use is refused by STS, KMS and Secrets Manager.

    GetCallerIdentity, ListKeys and ListSecrets signed with it fail as an invalid security token.
    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
    """
    iam = ctx.client("iam")

    user = ctx.unique_name("sim2real-keystate-user-")
    ctx.on_cleanup(lambda: _drop_user(iam, user))
    iam.create_user(UserName=user, Path="/", Tags=_MARK)

    ctx.on_cleanup(lambda: _drop_user_policy(iam, user))
    iam.put_user_policy(
        UserName=user,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kms:ListKeys", "secretsmanager:ListSecrets"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    ctx.on_cleanup(lambda: _drop_keys(iam, user))
    key = iam.create_access_key(UserName=user)["AccessKey"]
    # The key is deactivated before any call is signed with it: a key that has been used stays
    # honoured by other services' signers for a long time after it is deactivated.
    iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"], Status="Inactive")
    statuses = {
        meta["AccessKeyId"]: meta["Status"]
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user)
        for meta in page["AccessKeyMetadata"]
    }
    assert statuses == {key["AccessKeyId"]: "Inactive"}, (
        f"ListAccessKeys must report the one key Inactive after UpdateAccessKey; got {statuses!r}"
    )

    sts, kms, secrets = (_signing_as(ctx, svc, key) for svc in ("sts", "kms", "secretsmanager"))
    calls = {
        "sts GetCallerIdentity": lambda: sts.get_caller_identity(),
        "kms ListKeys": lambda: kms.list_keys(Limit=1),
        "secretsmanager ListSecrets": lambda: secrets.list_secrets(MaxResults=1),
    }
    expected = {
        "sts GetCallerIdentity": _STS_REFUSED,
        "kms ListKeys": _JSON_REFUSED,
        "secretsmanager ListSecrets": _JSON_REFUSED,
    }
    refused = _first_refusals(
        ctx, calls, description="the deactivated key is refused by every service"
    )
    assert refused == expected, (
        f"the key is Inactive, so each call signed with it must be refused as an invalid security "
        f"token with exactly {expected!r}; got {refused!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, less than the runner's remaining time so the poll fails first."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _first_refusals(ctx, calls, *, description, cap_s=_REVOCATION_S, interval_s=3.0):
    """Call each service until it refuses the key; return each service's first refusal.

    A key change reaches other services' signers asynchronously, so a call that still succeeds is
    retried until the shared deadline; a service that has refused is not called again.
    """
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    refused = {}
    while True:
        accepted = []
        for label, call in calls.items():
            if label not in refused:
                outcome = _outcome(call)
                if outcome == (_OK, ""):
                    accepted.append(label)
                else:
                    refused[label] = outcome
        if len(refused) == len(calls):
            return refused
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting: {description}")
            raise AssertionError(
                f"{description} did not happen within {timeout_s:.0f}s; still accepted by "
                f"{accepted!r}, refused so far {refused!r}"
            )
        time.sleep(interval_s)


def _outcome(fn):
    """``(code, message)`` of the call's error, or ``("OK", "")`` on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message", "")
    return _OK, ""


def _signing_as(ctx, service, key):
    """A client for ``service`` signing as the principal that owns ``key``."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )


def _tolerate_missing(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _drop_keys(iam, user):
    """Teardown: delete every key the user holds, including one whose create response was lost."""
    try:
        pages = list(iam.get_paginator("list_access_keys").paginate(UserName=user))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for page in pages:
        for meta in page["AccessKeyMetadata"]:
            key_id = meta["AccessKeyId"]
            _tolerate_missing(lambda k=key_id: iam.delete_access_key(UserName=user, AccessKeyId=k))


def _drop_user_policy(iam, user):
    _tolerate_missing(lambda: iam.delete_user_policy(UserName=user, PolicyName=_POLICY_NAME))


def _drop_user(iam, user):
    _tolerate_missing(lambda: iam.delete_user(UserName=user))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
