"""list-hypervisors-pagination."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-hypervisors-pagination"
GROUP = "lifecycle"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHypervisors with MaxResults=1 returns exactly one item per page plus a NextToken
    for every page that is not the last, and paging through all tokens eventually surfaces
    every hypervisor created in this check."""
    bg = ctx.client("backup-gateway")
    arn_a = _create_hypervisor(ctx)
    arn_b = _create_hypervisor(ctx)

    first_page = bg.list_hypervisors(MaxResults=1)
    first_hypervisors = first_page.get("Hypervisors", [])
    assert len(first_hypervisors) == 1, (
        f"expected exactly 1 hypervisor on the first MaxResults=1 page, got {len(first_hypervisors)}"
    )
    assert first_page.get("NextToken"), "expected a NextToken on the first page (2 hypervisors exist)"

    seen: set[str] = {h["HypervisorArn"] for h in first_hypervisors}
    token = first_page.get("NextToken")
    pages = 0
    while token and pages < 200:
        page = bg.list_hypervisors(MaxResults=1, NextToken=token)
        page_hypervisors = page.get("Hypervisors", [])
        next_token = page.get("NextToken")
        if next_token:
            # A page that hands back another NextToken is not the last page, so it must
            # be full: MaxResults=1 means exactly 1, not merely "at most 1".
            assert len(page_hypervisors) == 1, (
                f"expected exactly 1 hypervisor on a non-terminal MaxResults=1 page, "
                f"got {len(page_hypervisors)}"
            )
        else:
            assert len(page_hypervisors) <= 1, (
                f"expected at most 1 hypervisor on the terminal MaxResults=1 page, "
                f"got {len(page_hypervisors)}"
            )
        seen.update(h["HypervisorArn"] for h in page_hypervisors)
        token = next_token
        pages += 1

    assert arn_a in seen, f"expected {arn_a} to appear while paging ListHypervisors, seen={seen}"
    assert arn_b in seen, f"expected {arn_b} to appear while paging ListHypervisors, seen={seen}"


def _create_hypervisor(ctx, host=None, name=None):
    bg = ctx.client("backup-gateway")
    kwargs = {
        "Name": name or ctx.unique_name("sim2real-bgw-"),
        "Host": host or f"{ctx.unique_name('sim2real-bgw-host-')}.example.com",
        "Username": "sim2real-user",
        "Password": "Sim2Real-Passw0rd!",
        "Tags": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    }
    arn = bg.import_hypervisor_configuration(**kwargs)["HypervisorArn"]

    def _cleanup():
        try:
            bg.delete_hypervisor(HypervisorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
