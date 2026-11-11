"""get-dataset-nonexistent-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-dataset-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDataset on a dataset ARN in another account fails with AccessDenied "Caller account <own>
    is not authorized to access resource in account <foreign>", while GetDataset("default") returns
    the caller's own dataset ARN."""
    cw = ctx.client("cloudwatch")
    own_account_id = ctx.client("sts").get_caller_identity()["Account"]

    foreign_account_id = "111122223333" if own_account_id != "111122223333" else "210987654321"
    foreign_arn = f"arn:aws:cloudwatch:{ctx.region}:{foreign_account_id}:dataset/default"

    code, message = _error(lambda: cw.get_dataset(DatasetIdentifier=foreign_arn))
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    assert message == (
        f"Caller account {own_account_id} is not authorized to access resource in account {foreign_account_id}"
    ), f"unexpected AccessDenied message {message!r}"

    own = cw.get_dataset(DatasetIdentifier="default")
    expected_own_arn = f"arn:aws:cloudwatch:{ctx.region}:{own_account_id}:dataset/default"
    assert own["DatasetId"] == "default", f"expected DatasetId 'default', got {own['DatasetId']!r}"
    assert own["Arn"] == expected_own_arn, f"expected Arn {expected_own_arn!r}, got {own['Arn']!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
