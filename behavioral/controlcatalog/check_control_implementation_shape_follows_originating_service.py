"""control-implementation-shape-follows-originating-service."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-implementation-shape-follows-originating-service"
GROUP = "representation"
SERVICES = ["controlcatalog"]

_CONFIG_RULE_TYPE = "AWS::Config::ConfigRule"
_RESOURCE_POLICY_TYPE = "AWS::Organizations::Policy::RESOURCE_CONTROL_POLICY"


def _first_control_of_type(cc, implementation_type: str, max_pages: int):
    """The first ListControls entry whose Implementation.Type equals implementation_type."""
    next_token = None
    for _ in range(max_pages):
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cc.list_controls(**kwargs)
        for control in page["Controls"]:
            if (control.get("Implementation") or {}).get("Type") == implementation_type:
                return control
        next_token = page.get("NextToken")
        if not next_token:
            return None
    return None


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Config-rule control's Implementation carries Type plus a non-empty Identifier, equal
    between ListControls and GetControl; a resource-control-policy control's Implementation
    carries Type only on both reads, alongside a non-empty Aliases list.

    Reference: https://docs.aws.amazon.com/controltower/latest/APIReference/API_controlcatalog_ImplementationDetails.html
    """
    cc = ctx.client("controlcatalog")

    config_page = cc.list_controls(
        MaxResults=5, Filter={"Implementations": {"Types": [_CONFIG_RULE_TYPE]}}
    )["Controls"]
    assert config_page, f"ListControls filtered on {_CONFIG_RULE_TYPE!r} returned no controls"
    config_entry = config_page[0]
    config_detail = cc.get_control(ControlArn=config_entry["Arn"])

    list_impl = config_entry.get("Implementation") or {}
    get_impl = config_detail.get("Implementation") or {}
    assert sorted(list_impl) == ["Identifier", "Type"], (
        f"expected ListControls Implementation keys ['Identifier', 'Type'], got {sorted(list_impl)!r}"
    )
    assert sorted(get_impl) == ["Identifier", "Type"], (
        f"expected GetControl Implementation keys ['Identifier', 'Type'], got {sorted(get_impl)!r}"
    )
    assert list_impl["Type"] == _CONFIG_RULE_TYPE, (
        f"expected Implementation.Type {_CONFIG_RULE_TYPE!r}, got {list_impl['Type']!r}"
    )
    assert list_impl["Identifier"], f"expected a non-empty Identifier, got {list_impl['Identifier']!r}"
    assert get_impl == list_impl, (
        f"GetControl Implementation {get_impl!r} != ListControls Implementation {list_impl!r}"
    )

    rcp_entry = _first_control_of_type(cc, _RESOURCE_POLICY_TYPE, max_pages=25)
    assert rcp_entry is not None, (
        f"no control with Implementation.Type {_RESOURCE_POLICY_TYPE!r} found while scanning the catalog"
    )
    rcp_detail = cc.get_control(ControlArn=rcp_entry["Arn"])

    rcp_list_impl = rcp_entry.get("Implementation") or {}
    rcp_get_impl = rcp_detail.get("Implementation") or {}
    assert list(rcp_list_impl) == ["Type"], (
        f"expected ListControls Implementation to carry Type only, got keys {list(rcp_list_impl)!r}"
    )
    assert list(rcp_get_impl) == ["Type"], (
        f"expected GetControl Implementation to carry Type only, got keys {list(rcp_get_impl)!r}"
    )
    assert rcp_list_impl["Type"] == _RESOURCE_POLICY_TYPE, (
        f"expected Implementation.Type {_RESOURCE_POLICY_TYPE!r}, got {rcp_list_impl['Type']!r}"
    )
    assert rcp_get_impl == rcp_list_impl, (
        f"GetControl Implementation {rcp_get_impl!r} != ListControls Implementation {rcp_list_impl!r}"
    )

    list_aliases = rcp_entry.get("Aliases") or []
    get_aliases = rcp_detail.get("Aliases") or []
    assert list_aliases, f"expected a non-empty Aliases list from ListControls, got {list_aliases!r}"
    assert get_aliases, f"expected a non-empty Aliases list from GetControl, got {get_aliases!r}"
    assert sorted(get_aliases) == sorted(list_aliases), (
        f"GetControl Aliases {get_aliases!r} != ListControls Aliases {list_aliases!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
