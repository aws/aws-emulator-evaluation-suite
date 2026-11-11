"""batch-associate-resource-without-admin-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-associate-resource-without-admin-rejected"
GROUP = "overly-permissive"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With no Firewall Manager admin, BatchAssociateResource on a made-up resource set with a malformed item
    ARN fails with AccessDeniedException "No default admin could be found for account <id> in Region <region>",
    so the admin gate runs before any item or resource-set lookup."""
    fms = ctx.client("fms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    fake_rs_id = "0123456789AbCdEfGhIjKl"  # well-formed (22 base62 chars), nonexistent
    malformed_arn = "this-is-not-an-arn-at-all"
    well_formed_arn = f"arn:aws:network-firewall:{ctx.region}:{account_id}:firewall/{ctx.unique_name('fw-')}"

    code, message = _client_error(
        lambda: fms.batch_associate_resource(
            ResourceSetIdentifier=fake_rs_id, Items=[well_formed_arn, malformed_arn]
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", f"unexpected AccessDeniedException message: {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
