"""tag-resource-cross-account-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-cross-account-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tagging/reading a Connection ARN in a foreign account is denied, not treated as a same-account not-found."""
    ic = ctx.client("interconnect")
    sts = ctx.client("sts")
    own_account = sts.get_caller_identity()["Account"]
    foreign_account = "111111111111" if own_account != "111111111111" else "222222222222"
    foreign_arn = f"arn:aws:interconnect:{ctx.region}:{foreign_account}:connection/mcc-abcd1234"

    tag_code, tag_message = _error(lambda: ic.tag_resource(arn=foreign_arn, tags={"k": "v"}))
    assert tag_code == "InterconnectValidationException", f"got {tag_code!r}"
    assert tag_message == (
        f"ARN account ID ({foreign_account}) does not match caller account ID ({own_account}) "
        "for TagResourceRequest"
    ), f"got {tag_message!r}"

    # effect absent: reading the same foreign ARN is rejected the same way -- no tag state leaked or applied
    list_tags_code, list_tags_message = _error(lambda: ic.list_tags_for_resource(arn=foreign_arn))
    assert list_tags_code == "InterconnectValidationException", f"got {list_tags_code!r}"
    assert list_tags_message == (
        f"ARN account ID ({foreign_account}) does not match caller account ID ({own_account}) "
        "for ListTagsForResourceRequest"
    ), f"got {list_tags_message!r}"

    # positive control: the caller's own credentials still work fine against the service in general
    resp = ic.list_connections()
    assert "connections" in resp, f"expected a 'connections' key in the ListConnections response, got {resp!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
