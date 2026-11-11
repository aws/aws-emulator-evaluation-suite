"""control-aliases-consistent-between-get-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-aliases-consistent-between-get-and-list"
GROUP = "semantics"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A control's Aliases list returned by GetControl is identical to the Aliases list returned
    by ListControls for the same control ARN."""

    cc = ctx.client("controlcatalog")

    target = None
    next_token = None
    for _ in range(5):
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cc.list_controls(**kwargs)
        for c in page["Controls"]:
            if c.get("Aliases"):
                target = c
                break
        if target is not None or not page.get("NextToken"):
            break
        next_token = page["NextToken"]

    if target is None:
        raise AssertionError(
            "no control in the first ~500 scanned has a non-empty Aliases list; "
            "closeable by scanning the full catalog instead of the first 5 pages"
        )

    got = cc.get_control(ControlArn=target["Arn"])
    assert len(got.get("Aliases") or []) > 0, (
        f"GetControl returned no Aliases for {target['Arn']}, but ListControls reported {target['Aliases']}"
    )
    assert set(got.get("Aliases") or []) == set(target["Aliases"]), (
        f"GetControl Aliases {got.get('Aliases')} != ListControls Aliases {target['Aliases']} for {target['Arn']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
