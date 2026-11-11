"""start-change-set-invalid-client-request-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-change-set-invalid-client-request-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartChangeSet with a ClientRequestToken containing a space fails ValidationException with the exact
    pattern message, while the same request with a valid token fails ResourceNotFoundException on the
    missing entity, so the rejection is specific to the token."""
    # The Marketplace Catalog API is served in us-east-1 only, so the client pins that region.
    mp = ctx.client("marketplace-catalog", region="us-east-1")
    missing_entity = "prod-" + ctx.unique_name("sim2realbehav").replace("-", "")
    missing_entity_id = missing_entity + "@1"
    change = {
        "ChangeType": "AddRevisions",
        "Entity": {"Identifier": missing_entity_id, "Type": "DataProduct@1.0"},
        "Details": '{"DataSetArn": "data-set-arn", "RevisionArns": ["revision-arn"]}',
    }

    code, msg = _error_code(
        lambda: mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSet=[change],
            ClientRequestToken="has a space in it",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {msg}"
    expected = (
        "[Requested client request token 'has a space in it' is invalid. It should match with "
        + r"^[!-~]{1,64}$" + ".]"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    code2, msg2 = _error_code(
        lambda: mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSet=[change],
            ClientRequestToken=ctx.unique_name("sim2real-behav-"),
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}: {msg2}"
    expected2 = f"Requested entity '{missing_entity}' does not exist."
    assert msg2 == expected2, f"expected message {expected2!r}, got {msg2!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
