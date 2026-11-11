"""op-contract-describe-prefix-lists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-prefix-lists"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePrefixLists: returns the AWS-managed service prefix lists
    (e.g. the S3 prefix list for the region); DryRun=True rejects with
    DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_prefix_lists()
    prefix_lists = resp["PrefixLists"]
    assert isinstance(prefix_lists, list), f"expected PrefixLists to be a list, got {type(prefix_lists)!r}"
    assert len(prefix_lists) > 0, "expected at least the AWS-managed S3 prefix list"
    for pl in prefix_lists:
        assert pl["PrefixListId"].startswith("pl-"), f"expected a pl- id, got {pl['PrefixListId']!r}"
        assert pl["PrefixListName"], f"expected a non-empty PrefixListName, got {pl.get('PrefixListName')!r}"
        assert pl["Cidrs"] and isinstance(pl["Cidrs"], list), (
            f"expected a non-empty Cidrs list, got {pl.get('Cidrs')!r}"
        )
    s3_name_fragment = f".{ctx.region}.s3"
    assert any(s3_name_fragment in pl["PrefixListName"] for pl in prefix_lists), (
        f"expected a prefix list containing {s3_name_fragment!r}, got names "
        f"{[pl['PrefixListName'] for pl in prefix_lists]}"
    )

    code, msg = _client_error(lambda: ec2.describe_prefix_lists(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
