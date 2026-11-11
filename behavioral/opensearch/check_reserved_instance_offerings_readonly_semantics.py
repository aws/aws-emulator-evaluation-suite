"""reserved-instance-offerings-readonly-semantics."""
from __future__ import annotations
from botocore.exceptions import ClientError
from behavioral_harness import tags
CHECK = "reserved-instance-offerings-readonly-semantics"
GROUP = 'reserved-instances'
SERVICES = ['opensearch']

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reserved instance offerings carry fields consistent with their PaymentOption pricing, and
    DescribeReservedInstances with a nonexistent id raises ResourceNotFoundException.
    Purchases are not exercised: PurchaseReservedInstanceOffering is a non-refundable billing event.
    """
    os = ctx.client('opensearch')
    resp = os.describe_reserved_instance_offerings()
    offerings = resp.get('ReservedInstanceOfferings', [])
    if not offerings:
        raise AssertionError('no ReservedInstanceOfferings available in this account/region')
    offering = offerings[0]
    assert offering.get('ReservedInstanceOfferingId'), 'offering is missing its id'
    payment_option = offering.get('PaymentOption')
    assert payment_option in ('ALL_UPFRONT', 'PARTIAL_UPFRONT', 'NO_UPFRONT'), f"unexpected PaymentOption {payment_option}"
    duration = offering.get('Duration')
    assert isinstance(duration, int) and duration > 0, f'expected a positive integer Duration, got {duration!r}'
    assert offering.get('CurrencyCode'), 'offering is missing CurrencyCode'
    fixed_price = offering.get('FixedPrice')
    usage_price = offering.get('UsagePrice')
    if payment_option == 'ALL_UPFRONT':
        assert fixed_price is not None and fixed_price > 0, f'ALL_UPFRONT must carry a positive FixedPrice, got {fixed_price!r}'
        assert usage_price == 0, f'ALL_UPFRONT must carry a zero UsagePrice, got {usage_price!r}'
    elif payment_option == 'NO_UPFRONT':
        assert fixed_price == 0, f'NO_UPFRONT must carry a zero FixedPrice, got {fixed_price!r}'
        assert usage_price is not None and usage_price > 0, f'NO_UPFRONT must carry a positive UsagePrice, got {usage_price!r}'
    else:
        assert fixed_price is not None and fixed_price > 0, f'PARTIAL_UPFRONT must carry a positive FixedPrice, got {fixed_price!r}'
        assert usage_price is not None and usage_price > 0, f'PARTIAL_UPFRONT must carry a positive UsagePrice, got {usage_price!r}'

    # Positive control: the unfiltered call succeeds, so the not-found below is input-specific.
    listed = os.describe_reserved_instances()
    assert isinstance(listed.get('ReservedInstances'), list), 'unfiltered DescribeReservedInstances must return a list, proving the operation is reachable on this account/wiring'

    try:
        result = os.describe_reserved_instances(ReservedInstanceId='11111111-2222-3333-4444-555555555555')
    except ClientError as _e:
        code = _e.response.get('Error', {}).get('Code')
        message = _e.response.get('Error', {}).get('Message')
    else:
        raise AssertionError(f'a nonexistent ReservedInstanceId must be rejected, but the call SUCCEEDED and returned {result!r}')
    assert code == 'ResourceNotFoundException', f'expected ResourceNotFoundException, got {code}'
    assert message == 'Reservation id not found', f'unexpected not-found message: {message!r}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
