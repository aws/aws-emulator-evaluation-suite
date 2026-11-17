"""list-secret-version-ids-max-results-out-of-range-and-fabricated-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-secret-version-ids-max-results-out-of-range-and-fabricated-next-token-rejected"
GROUP = "validation"
SERVICES = ["secretsmanager"]


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    """ListSecretVersionIds refuses MaxResults above 100 and a fabricated NextToken, while
    MaxResults=100 at the boundary and a real NextToken still page the secret's versions.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-lsvibad-")
    created = sm.create_secret(
        Name=name,
        SecretString="sim2real-not-a-real-secret",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: _force_delete(sm, secret_arn))
    sm.put_secret_value(SecretId=secret_arn, SecretString="sim2real-not-a-real-secret-v2")

    code, message = _refusal(lambda: sm.list_secret_version_ids(SecretId=secret_arn, MaxResults=101))
    assert code == "ValidationException", f"MaxResults=101 must be refused, got {code!r}: {message!r}"
    expected = (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert message == expected, f"unexpected message for MaxResults=101: {message!r}"

    code, message = _refusal(
        lambda: sm.list_secret_version_ids(SecretId=secret_arn, NextToken="sim2real-not-a-real-token")
    )
    assert code == "InvalidNextTokenException", f"a fabricated NextToken must be refused, got {code!r}: {message!r}"
    expected = "The pagination token is no longer valid."
    assert message == expected, f"unexpected message for a fabricated NextToken: {message!r}"

    # Positive control: the boundary value and a real NextToken still page every version.
    first = sm.list_secret_version_ids(SecretId=secret_arn, MaxResults=1)
    ids = {v["VersionId"] for v in first["Versions"]}
    token = first.get("NextToken")
    assert token, f"MaxResults=1 with two versions must carry a NextToken, got {first!r}"
    second = sm.list_secret_version_ids(SecretId=secret_arn, MaxResults=100, NextToken=token)
    ids |= {v["VersionId"] for v in second["Versions"]}
    assert len(ids) == 2 and created["VersionId"] in ids, (
        f"paging with MaxResults=1 then MaxResults=100 must together list both versions, got {ids!r}"
    )
    assert "NextToken" not in second, f"the final page must omit NextToken, got {second.get('NextToken')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
