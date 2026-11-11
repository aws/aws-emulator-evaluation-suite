"""get-control-region-configuration-regional-scope."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-control-region-configuration-regional-scope"
GROUP = "data-plane"
SERVICES = ["controlcatalog"]

_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+){1,2}-\d$")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A REGIONAL-scope control's RegionConfiguration lists a non-empty set of well-formed deployable Regions."""
    cc = ctx.client("controlcatalog")
    token = None
    checked = 0
    for _ in range(3):
        kwargs = {"MaxResults": 10}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_controls(**kwargs)
        for summary in page.get("Controls", []):
            checked += 1
            detail = cc.get_control(ControlArn=summary["Arn"])
            region_conf = detail["RegionConfiguration"]
            scope = region_conf["Scope"]
            assert scope in ("REGIONAL", "GLOBAL"), f"unexpected RegionConfiguration.Scope {scope!r} on {summary['Arn']}"
            if scope == "REGIONAL":
                deployable = region_conf.get("DeployableRegions") or []
                assert len(deployable) > 0, f"REGIONAL control {summary['Arn']} reported no DeployableRegions"
                for r in deployable:
                    assert _REGION_RE.match(r), f"malformed region code {r!r} in DeployableRegions for {summary['Arn']}"
                return
        token = page.get("NextToken")
        if not token:
            break
    raise AssertionError(f"no REGIONAL-scope control found among {checked} controls scanned")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
