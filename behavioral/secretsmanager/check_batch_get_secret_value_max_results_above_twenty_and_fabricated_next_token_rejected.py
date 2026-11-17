"""batch-get-secret-value-max-results-above-twenty-and-fabricated-next-token-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-secret-value-max-results-above-twenty-and-fabricated-next-token-rejected"
GROUP = "validation"
SERVICES = ["secretsmanager"]


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _refusal(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetSecretValue refuses MaxResults above 20 and a fabricated NextToken on the Filters
    form, while MaxResults=20 at the boundary still serves the secret filtered to.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-bgvbad-")
    created = sm.create_secret(
        Name=name,
        SecretString="sim2real-not-a-real-secret",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete(sm, created["ARN"]))
    own = [{"Key": "name", "Values": [name]}]

    def _by_filter():
        return sm.batch_get_secret_value(Filters=own, MaxResults=20)

    settled = _poll(_by_filter, lambda got: len(got["SecretValues"]) == 1)
    served = [(e["Name"], e["VersionId"]) for e in settled["SecretValues"]]
    assert served == [(name, created["VersionId"])], (
        f"the name filter must converge on the one secret just created, got {served!r}"
    )

    code, message = _refusal(lambda: sm.batch_get_secret_value(Filters=own, MaxResults=21))
    assert code == "InvalidRequestException", f"MaxResults=21 must be refused, got {code!r}: {message!r}"
    expected = "Max results must not exceed 20."
    assert message == expected, f"unexpected message for MaxResults=21: {message!r}"

    code, message = _refusal(
        lambda: sm.batch_get_secret_value(Filters=own, NextToken="sim2real-not-a-real-token")
    )
    assert code == "InvalidNextTokenException", f"a fabricated NextToken must be refused, got {code!r}: {message!r}"
    expected = "The pagination token is no longer valid."
    assert message == expected, f"unexpected message for a fabricated NextToken: {message!r}"

    # Positive control: the identical call at the boundary still serves the one secret.
    ok = _by_filter()
    served = [(e["Name"], e["VersionId"]) for e in ok["SecretValues"]]
    assert served == [(name, created["VersionId"])], (
        f"MaxResults=20 with the name filter must serve exactly the one secret, got {served!r}"
    )
    assert "NextToken" not in ok, f"a single-match page must omit NextToken, got {ok.get('NextToken')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
