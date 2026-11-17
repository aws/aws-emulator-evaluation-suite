"""list-grants-and-list-resource-tags-limit-over-max-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-grants-and-list-resource-tags-limit-over-max-rejected"
GROUP = 'errors'
SERVICES = ['kms']

_LIMIT_OVER_MAX = (
    "ValidationException",
    "1 validation error detected: Value '1001' at 'limit' failed to satisfy constraint: "
    "Member must have value less than or equal to 1000",
)


def _refusal(fn):
    """The (Code, Message) pair of the ClientError fn() raises; raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error["Message"]
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListGrants and ListResourceTags accept Limit up to 1000 and reject Limit=1001 with the
    documented ValidationException.
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    grants_at_max = kms.list_grants(KeyId=key_id, Limit=1000)
    assert grants_at_max["Grants"] == [], f"expected no grants at Limit=1000, got {grants_at_max['Grants']!r}"
    tags_at_max = kms.list_resource_tags(KeyId=key_id, Limit=1000)
    assert tags_at_max["Tags"] == [], f"expected no tags at Limit=1000, got {tags_at_max['Tags']!r}"

    got_grants = _refusal(lambda: kms.list_grants(KeyId=key_id, Limit=1001))
    assert got_grants == _LIMIT_OVER_MAX, (
        f"ListGrants Limit=1001: expected {_LIMIT_OVER_MAX!r}, got {got_grants!r}"
    )
    got_tags = _refusal(lambda: kms.list_resource_tags(KeyId=key_id, Limit=1001))
    assert got_tags == _LIMIT_OVER_MAX, (
        f"ListResourceTags Limit=1001: expected {_LIMIT_OVER_MAX!r}, got {got_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
