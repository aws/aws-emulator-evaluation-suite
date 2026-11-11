"""update-link-resource-types-replaces-not-merges."""
from __future__ import annotations

import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-link-resource-types-replaces-not-merges"
GROUP = "error-semantics"
SERVICES = ["oam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateLink on a well-formed never-created link fails with the identical AccessDeniedException
    message whether ResourceTypes is missing, empty (both sent with client-side validation off) or
    valid: access control runs before shape validation."""
    oam = ctx.client("oam")
    novalidate_oam = ctx.client("oam", config=Config(parameter_validation=False))
    account_id = _own_account_id(ctx)
    region = ctx.region
    bogus_arn = f"arn:aws:oam:{region}:{account_id}:link/{uuid.uuid4()}"
    link_deny = _explicit_deny_message(ctx, "UpdateLink", f"arn:aws:oam:{region}:{account_id}:link/*")

    # omitting ResourceTypes entirely (required member) never reaches shape validation -- the
    # access-control check on the nonexistent identifier fires first. parameter_validation=False
    # forces the request onto the wire so a target that validates shape before access control
    # (and would therefore answer differently) is caught.
    missing_code, missing_code_message = _error(lambda: novalidate_oam.update_link(Identifier=bogus_arn))
    assert missing_code == "AccessDeniedException", f"got {missing_code!r}"
    assert missing_code_message == link_deny, f"got message {missing_code_message!r}"

    # an empty ResourceTypes list (length min 1) hits the identical access-control gate, not a
    # distinct empty-list shape error -- same ordering as the missing-member case above.
    empty_code, empty_code_message = _error(
        lambda: novalidate_oam.update_link(Identifier=bogus_arn, ResourceTypes=[])
    )
    assert empty_code == "AccessDeniedException", f"got {empty_code!r}"
    assert empty_code_message == link_deny, f"got message {empty_code_message!r}"

    # a well-formed, non-empty ResourceTypes against the same nonexistent identifier hits the same
    # access-control path -- confirming ResourceTypes' shape plays no part in which error the
    # missing/empty cases above receive.
    valid_code, valid_code_message = _error(
        lambda: oam.update_link(Identifier=bogus_arn, ResourceTypes=["AWS::CloudWatch::Metric"])
    )
    assert valid_code == "AccessDeniedException", f"got {valid_code!r}"
    assert valid_code_message == link_deny, f"got message {valid_code_message!r}"


def _explicit_deny_message(ctx, action, resource):
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    return (
        f"User: {caller} is not authorized to perform: oam:{action} on resource: {resource} "
        "with an explicit deny in a resource-based policy"
    )


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _own_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

