"""get-dataset-not-found-for-unknown-dataset."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-dataset-not-found-for-unknown-dataset"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDataset("default") returns the caller's own dataset ARN, while a dataset ARN in account
    111122223333 fails with AccessDenied "Caller account <own> is not authorized to access resource
    in account 111122223333", not ResourceNotFoundException."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "get_dataset"):
        raise AssertionError("cloudwatch client does not support GetDataset")

    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    own = cw.get_dataset(DatasetIdentifier="default")
    assert own["DatasetId"] == "default", (
        f"expected DatasetId 'default', got {own.get('DatasetId')!r}"
    )
    assert own["Arn"] == f"arn:aws:cloudwatch:{ctx.region}:{own_account_id}:dataset/default", (
        f"expected own-account dataset ARN, got {own.get('Arn')!r}"
    )

    # DatasetIdentifier must match the pattern (default|arn:...:dataset/default); the only way to
    # reference a dataset outside the caller's own account while satisfying that pattern is a
    # syntactically valid ARN for a foreign account.
    bogus_arn = f"arn:aws:cloudwatch:{ctx.region}:111122223333:dataset/default"
    code, message = _error(lambda: cw.get_dataset(DatasetIdentifier=bogus_arn))
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    assert message == (
        f"Caller account {own_account_id} is not authorized to access resource in account 111122223333"
    ), f"unexpected AccessDenied message {message!r}"


from botocore.exceptions import ClientError  # noqa: E402


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {}).get("Code"), e.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
