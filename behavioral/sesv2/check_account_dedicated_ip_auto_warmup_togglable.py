"""account-dedicated-ip-auto-warmup-togglable."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-dedicated-ip-auto-warmup-togglable"
GROUP = 'dedicated-ip-account-attributes'
SERVICES = ['sesv2']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutAccountDedicatedIpWarmupAttributes flips DedicatedIpAutoWarmupEnabled, GetAccount reflects
    it on the next read, and restoring the original value is reflected too.
    """
    sesv2 = ctx.client('sesv2')

    original = sesv2.get_account()['DedicatedIpAutoWarmupEnabled']
    sesv2.put_account_dedicated_ip_warmup_attributes(AutoWarmupEnabled=not original)
    ctx.on_cleanup(lambda: sesv2.put_account_dedicated_ip_warmup_attributes(AutoWarmupEnabled=original))

    flipped = sesv2.get_account()['DedicatedIpAutoWarmupEnabled']
    assert flipped == (not original), (
        f"expected DedicatedIpAutoWarmupEnabled to flip to {not original!r}, GetAccount reports {flipped!r}"
    )

    sesv2.put_account_dedicated_ip_warmup_attributes(AutoWarmupEnabled=original)
    restored = sesv2.get_account()['DedicatedIpAutoWarmupEnabled']
    assert restored == original, (
        f"expected DedicatedIpAutoWarmupEnabled restored to {original!r}, GetAccount reports {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
