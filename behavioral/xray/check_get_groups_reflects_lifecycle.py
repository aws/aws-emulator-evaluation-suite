"""get-groups-reflects-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-groups-reflects-lifecycle"
GROUP = 'groups'
SERVICES = ['xray']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroups is a live view of group state: a created group appears in the paginated summary
    list and disappears once deleted."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    xr.create_group(
        GroupName=name,
        FilterExpression='service("gg")',
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup():
        try:
            xr.delete_group(GroupName=name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != ("InvalidRequestException", "Group not found"):
                raise

    ctx.on_cleanup(_cleanup)

    def names():
        out, token = [], None
        while True:
            kwargs = {"NextToken": token} if token else {}
            resp = xr.get_groups(**kwargs)
            out.extend(g["GroupName"] for g in resp.get("Groups", []))
            token = resp.get("NextToken")
            if not token:
                return out

    assert name in names(), "newly created group missing from GetGroups"

    xr.delete_group(GroupName=name)
    assert name not in names(), "deleted group still present in GetGroups"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
