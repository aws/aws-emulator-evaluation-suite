"""parameter-store-reference-fails-until-the-secret-exists-then-serves-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-store-reference-fails-until-the-secret-exists-then-serves-it"
GROUP = "lifecycle"
SERVICES = ["secretsmanager", "ssm"]

_PREFIX = "aws/reference/secretsmanager"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A /aws/reference/secretsmanager/<name> read fails ParameterNotFound and is reported
    invalid in a batch read before the secret exists, and both calls serve its value once
    CreateSecret creates it.
    """
    sm = ctx.client("secretsmanager")
    ssm = ctx.client("ssm")

    name = ctx.unique_name("sim2real-behav-smssmcreate-")
    ref = f"/{_PREFIX}/{name}"
    not_found = ("ParameterNotFound", (
        f"An error occurred (ParameterNotFound) when referencing Secrets Manager: Secret "
        f"{_PREFIX}/{name} not found. Secrets Manager can't find the specified secret."
    ))

    _expect_error(lambda: ssm.get_parameter(Name=ref, WithDecryption=True), *not_found)

    before = ssm.get_parameters(Names=[ref], WithDecryption=True)
    assert before["Parameters"] == [], (
        f"GetParameters on a never-created reference must report no Parameters; got "
        f"{before['Parameters']!r}"
    )
    assert before["InvalidParameters"] == [ref], (
        f"GetParameters must report the missing reference as the sole InvalidParameters entry; "
        f"got {before['InvalidParameters']!r}"
    )

    secret_value = json.dumps({"username": "app", "password": "initial-pw"})
    created = sm.create_secret(
        Name=name,
        SecretString=secret_value,
        Description="sim2real behavioral draft: a Parameter Store reference created after a miss",
        Tags=_sim2real_tags(),
    )
    arn = created["ARN"]
    ctx.on_cleanup(_teardown(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)))

    resolved = _poll(
        lambda: _get_parameter(ssm, ref),
        lambda r: r[0] == "OK",
        timeout_s=90.0,
        interval_s=3.0,
        description=(
            f"the reference {ref!r} to become resolvable now that the secret exists (the front "
            f"door is a different service from the store and may lag CreateSecret)"
        ),
    )
    param = resolved[1]
    assert param["Value"] == secret_value, (
        f"GetParameter on {ref!r} must serve the secret's own SecretString byte-for-byte; expected "
        f"{secret_value!r}, got {param.get('Value')!r}"
    )
    assert param["Type"] == "SecureString", (
        f"a Secrets Manager reference must be presented as SecureString; got Type={param.get('Type')!r}"
    )
    assert param["Name"] == ref, (
        f"the echoed parameter name must be the reference path; expected {ref!r}, got "
        f"{param.get('Name')!r}"
    )

    after = _poll(
        lambda: ssm.get_parameters(Names=[ref], WithDecryption=True),
        lambda r: r["InvalidParameters"] == [],
        timeout_s=90.0,
        interval_s=3.0,
        description=(
            f"the batch read of {ref!r} to stop reporting InvalidParameters now that the secret "
            f"exists (its propagation lags the single-parameter read independently)"
        ),
    )
    assert len(after["Parameters"]) == 1, (
        f"GetParameters must report exactly one resolved Parameter for {ref!r}; got "
        f"{after['Parameters']!r}"
    )
    batch_param = after["Parameters"][0]
    assert batch_param["Value"] == secret_value, (
        f"the batch read must serve the same bytes as GetParameter; expected {secret_value!r}, got "
        f"{batch_param.get('Value')!r}"
    )
    assert batch_param["Name"] == ref, (
        f"the batch read must echo the reference path; expected {ref!r}, got "
        f"{batch_param.get('Name')!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code and err.get("Message") == message, (
            f"expected ({code!r}, {message!r}), got ({err.get('Code')!r}, {err.get('Message')!r})"
        )
        return
    raise AssertionError(f"expected the call to be refused with {code!r}, but it succeeded: {result!r}")


def _get_parameter(ssm, name: str):
    """Return (code or 'OK', Parameter or None)."""
    try:
        resp = ssm.get_parameter(Name=name, WithDecryption=True)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None
    return "OK", resp["Parameter"]


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout, never returning its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
