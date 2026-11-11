"""list-secrets-invalid-filter-key-value-and-page-size-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
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
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, extra_tags=(), **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}, *extra_tags], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _refusal(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=150.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


CHECK = "list-secrets-invalid-filter-key-value-and-page-size-rejected"
GROUP = "validation"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSecrets refuses an unknown filter key, a filter value outside the allowed character set,
    MaxResults above 100 and an unknown SortBy with ValidationException, while valid parameters
    still list the check's secret; botocore validates none of these client-side."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-lsbad-")
    _create_secret(sm, ctx, name, SecretString="sim2real-not-a-real-secret")
    own = [{"Key": "name", "Values": [name]}]

    def names(**kw):
        return sorted(s["Name"] for s in sm.list_secrets(Filters=own, **kw)["SecretList"])

    settled = _poll(lambda: names(), lambda got: got == [name])
    assert settled == [name], f"the name filter must converge on the created secret, got {settled}"

    code, message = _refusal(
        lambda: sm.list_secrets(Filters=[{"Key": "secret-name", "Values": [name]}]))
    assert code == "ValidationException", f"an unknown filter key must be refused, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'secret-name' at 'filters.1.member.key' failed to "
        "satisfy constraint: Member must satisfy enum value set: "
        "[all, owning-service, name, tag-key, description, tag-value, primary-region]"
    ), f"unexpected message for an unknown filter key: {message!r}"

    code, message = _refusal(
        lambda: sm.list_secrets(Filters=[{"Key": "name", "Values": [f"{name}*"]}]))
    assert code == "ValidationException", f"a '*' in a filter value must be refused, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '[{name}*]' at 'filters.1.member.values' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must have length less than "
        "or equal to 512, Member must have length greater than or equal to 0, Member must "
        "satisfy regular expression pattern: ^\\!?[a-zA-Z0-9 :_@\\/\\+\\=\\.\\-\\!]*$]"
    ), f"unexpected message for a '*' filter value: {message!r}"

    code, message = _refusal(lambda: sm.list_secrets(Filters=own, MaxResults=101))
    assert code == "ValidationException", f"MaxResults=101 must be refused, got {code!r}"
    assert message == (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), f"unexpected message for MaxResults=101: {message!r}"

    code, message = _refusal(lambda: sm.list_secrets(Filters=own, SortBy="updated-date"))
    assert code == "ValidationException", f"an unknown SortBy must be refused, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'updated-date' at 'sortBy' failed to satisfy "
        "constraint: Member must satisfy enum value set: "
        "[last-accessed-date, name, created-date, last-changed-date]"
    ), f"unexpected message for an unknown SortBy: {message!r}"

    # Positive controls at the boundaries the refusals sit just past.
    assert names(MaxResults=100) == [name], "MaxResults=100 is the documented maximum and must list"
    assert names(SortBy="last-changed-date") == [name], "a valid SortBy must list the secret"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
