"""describe-prefix-lists-unknown-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-prefix-lists-unknown-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePrefixLists rejects a well-formed but nonexistent PrefixListId, and a real,
    AWS-managed prefix list id is still returned by its own id."""
    ec2 = ctx.client("ec2")

    managed = ec2.describe_prefix_lists()["PrefixLists"]
    assert managed, "expected at least the AWS-managed S3 prefix list"
    real_id = managed[0]["PrefixListId"]

    bogus_id = _bogus_id_like(real_id)
    code, message = _error(lambda: ec2.describe_prefix_lists(PrefixListIds=[bogus_id]))
    assert code == "InvalidPrefixListId.NotFound", (
        f"expected InvalidPrefixListId.NotFound, got {code}: {message}"
    )
    expected_message = f"The Prefix List Id '{bogus_id}' does not exist"
    assert message == expected_message, f"unexpected message: {message!r}"

    # positive control: the real id, on the same wiring, is found.
    found = ec2.describe_prefix_lists(PrefixListIds=[real_id])["PrefixLists"]
    assert len(found) == 1 and found[0]["PrefixListId"] == real_id, (
        f"expected exactly {real_id!r} back, got {found!r}"
    )


def _bogus_id_like(real_id: str) -> str:
    """A well-formed id of the same prefix and length, guaranteed not to be ``real_id``."""
    prefix, _, suffix = real_id.partition("-")
    flipped = "".join("0" if c != "0" else "1" for c in suffix)
    return f"{prefix}-{flipped}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
