#!/usr/bin/env python3
"""
MEXC Balance Test Script

Tests MEXC API directly to verify balance capture across all account types.
This helps diagnose issues with the unified CCXT integration.

Usage:
    python scripts/test-mexc-balance.py

Install dependencies:
    pip install ccxt
"""

import sys
from datetime import datetime, timedelta

# ============================================================================
#  CONFIGURATION - Mettre vos credentials ici
# ============================================================================
API_KEY = 'VOTRE_API_KEY_ICI'
API_SECRET = 'VOTRE_API_SECRET_ICI'
# ============================================================================

try:
    import ccxt
except ImportError:
    print("Error: ccxt not installed. Run: pip install ccxt")
    sys.exit(1)


def create_mexc_client() -> ccxt.Exchange:
    """Create MEXC exchange client with credentials."""
    if API_KEY == 'VOTRE_API_KEY_ICI' or API_SECRET == 'VOTRE_API_SECRET_ICI':
        print("Error: Configurez vos credentials en haut du fichier!")
        print("\nOuvrez scripts/test-mexc-balance.py et modifiez:")
        print("  API_KEY = 'votre_vraie_api_key'")
        print("  API_SECRET = 'votre_vrai_secret'")
        sys.exit(1)

    return ccxt.mexc({
        'apiKey': API_KEY,
        'secret': API_SECRET,
        'enableRateLimit': True,
        'options': {
            'recvWindow': 10000,
        }
    })


def format_currency(value: float, decimals: int = 4) -> str:
    """Format currency value with proper decimal places."""
    return f"{value:,.{decimals}f}"


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def test_spot_balance(exchange: ccxt.Exchange) -> dict:
    """Test SPOT market balance."""
    print_section("SPOT BALANCE")

    exchange.options['defaultType'] = 'spot'

    try:
        balance = exchange.fetch_balance({'type': 'spot'})

        total_usdt_equiv = 0.0
        assets_with_balance = []

        # Get all non-zero balances
        for currency, data in balance.items():
            if currency in ['info', 'free', 'used', 'total', 'debt', 'timestamp', 'datetime']:
                continue

            if isinstance(data, dict):
                total = float(data.get('total', 0) or 0)
                free = float(data.get('free', 0) or 0)
                used = float(data.get('used', 0) or 0)

                if total > 0:
                    assets_with_balance.append({
                        'currency': currency,
                        'total': total,
                        'free': free,
                        'used': used
                    })

                    # Add to USDT equivalent (simplified: only USDT counted directly)
                    if currency in ['USDT', 'USDC', 'USD']:
                        total_usdt_equiv += total

        print(f"\nAssets with balance ({len(assets_with_balance)}):")
        print("-" * 50)

        for asset in sorted(assets_with_balance, key=lambda x: x['total'], reverse=True):
            print(f"  {asset['currency']:>10}: Total={format_currency(asset['total'], 8)}, "
                  f"Free={format_currency(asset['free'], 8)}, Used={format_currency(asset['used'], 8)}")

        print(f"\n>>> SPOT Stablecoin Total: {format_currency(total_usdt_equiv)} USDT equiv")

        return {
            'usdt_equiv': total_usdt_equiv,
            'assets': assets_with_balance,
            'raw': balance
        }

    except Exception as e:
        print(f"Error fetching spot balance: {e}")
        return {'usdt_equiv': 0, 'assets': [], 'error': str(e)}


def test_swap_balance(exchange: ccxt.Exchange) -> dict:
    """Test SWAP/Futures market balance."""
    print_section("SWAP/FUTURES BALANCE")

    exchange.options['defaultType'] = 'swap'

    try:
        balance = exchange.fetch_balance()

        usdt = balance.get('USDT', {})
        usdc = balance.get('USDC', {})
        usd = balance.get('USD', {})

        usdt_total = float(usdt.get('total', 0) or 0)
        usdt_free = float(usdt.get('free', 0) or 0)
        usdt_used = float(usdt.get('used', 0) or 0)

        usdc_total = float(usdc.get('total', 0) or 0)
        usd_total = float(usd.get('total', 0) or 0)

        print(f"\nUSDT Balance:")
        print(f"  Total:     {format_currency(usdt_total)}")
        print(f"  Free:      {format_currency(usdt_free)}")
        print(f"  Used:      {format_currency(usdt_used)}")

        if usdc_total > 0:
            print(f"\nUSDC Balance: {format_currency(usdc_total)}")
        if usd_total > 0:
            print(f"USD Balance:  {format_currency(usd_total)}")

        total = usdt_total + usdc_total + usd_total
        print(f"\n>>> SWAP Total Equity: {format_currency(total)} USD equiv")

        return {
            'usdt_total': usdt_total,
            'usdt_free': usdt_free,
            'usdc_total': usdc_total,
            'total': total,
            'raw': balance
        }

    except Exception as e:
        print(f"Error fetching swap balance: {e}")
        return {'total': 0, 'error': str(e)}


def test_positions(exchange: ccxt.Exchange) -> dict:
    """Test open positions."""
    print_section("OPEN POSITIONS")

    exchange.options['defaultType'] = 'swap'

    try:
        positions = exchange.fetch_positions()
        open_positions = [p for p in positions if p.get('contracts', 0) and float(p['contracts']) > 0]

        total_unrealized_pnl = 0.0
        total_notional = 0.0

        if not open_positions:
            print("\nNo open positions")
        else:
            print(f"\nOpen positions ({len(open_positions)}):")
            print("-" * 80)

            for pos in open_positions:
                symbol = pos.get('symbol', 'Unknown')
                side = pos.get('side', 'Unknown')
                contracts = float(pos.get('contracts', 0) or 0)
                entry = float(pos.get('entryPrice', 0) or 0)
                mark = float(pos.get('markPrice', 0) or 0)
                pnl = float(pos.get('unrealizedPnl', 0) or 0)
                notional = float(pos.get('notional', 0) or 0)
                leverage = pos.get('leverage', 1)

                total_unrealized_pnl += pnl
                total_notional += abs(notional)

                print(f"  {symbol:>20} | {side:>5} | Size: {contracts:>10.4f} | "
                      f"Entry: {entry:>10.4f} | Mark: {mark:>10.4f} | PnL: {pnl:>+10.2f}")

        print(f"\n>>> Total Unrealized PnL: {format_currency(total_unrealized_pnl)} USDT")
        print(f">>> Total Notional Value: {format_currency(total_notional)} USD")

        return {
            'positions': open_positions,
            'unrealized_pnl': total_unrealized_pnl,
            'notional': total_notional
        }

    except Exception as e:
        print(f"Error fetching positions: {e}")
        return {'positions': [], 'unrealized_pnl': 0, 'error': str(e)}


def test_market_types(exchange: ccxt.Exchange) -> list:
    """Detect available market types."""
    print_section("MARKET TYPES DETECTION")

    try:
        exchange.load_markets()
        market_types = set()

        for market in exchange.markets.values():
            if market.get('spot'):
                market_types.add('spot')
            if market.get('swap'):
                market_types.add('swap')
            if market.get('future'):
                market_types.add('future')
            if market.get('option'):
                market_types.add('options')
            if market.get('margin'):
                market_types.add('margin')

        types_list = list(market_types)
        print(f"\nDetected market types: {', '.join(types_list)}")

        return types_list

    except Exception as e:
        print(f"Error detecting market types: {e}")
        return []


def test_recent_trades(exchange: ccxt.Exchange, days: int = 7) -> dict:
    """Test fetching recent trades."""
    print_section(f"RECENT TRADES (last {days} days)")

    since = int((datetime.utcnow() - timedelta(days=days)).timestamp() * 1000)

    # Try to get symbols from closed orders first
    symbols_to_check = set()

    try:
        exchange.options['defaultType'] = 'swap'
        closed_orders = exchange.fetch_closed_orders(None, since)
        for order in closed_orders:
            if order.get('symbol'):
                symbols_to_check.add(order['symbol'])
        print(f"\nFound {len(symbols_to_check)} symbols from closed orders")
    except Exception as e:
        print(f"Could not fetch closed orders: {e}")

    # Fetch trades for each symbol
    all_trades = []
    exchange.options['defaultType'] = 'swap'

    for symbol in symbols_to_check:
        try:
            trades = exchange.fetch_my_trades(symbol, since)
            all_trades.extend(trades)
            if trades:
                print(f"  {symbol}: {len(trades)} trades")
        except Exception:
            pass

    total_volume = sum(float(t.get('cost', 0) or 0) for t in all_trades)
    total_fees = sum(float(t.get('fee', {}).get('cost', 0) or 0) for t in all_trades)

    print(f"\n>>> Total trades: {len(all_trades)}")
    print(f">>> Total volume: {format_currency(total_volume)} USD")
    print(f">>> Total fees: {format_currency(total_fees)} USD")

    return {
        'trades': len(all_trades),
        'volume': total_volume,
        'fees': total_fees
    }


def test_funding_balance(exchange: ccxt.Exchange) -> dict:
    """Test funding/earn balance if available."""
    print_section("FUNDING/EARN BALANCE")

    for balance_type in ['funding', 'earn', 'savings']:
        try:
            balance = exchange.fetch_balance({'type': balance_type})
            usdt = balance.get('USDT', {})
            total = float(usdt.get('total', 0) or 0)

            if total > 0:
                print(f"\n{balance_type.upper()} USDT: {format_currency(total)}")
                return {'type': balance_type, 'total': total}
        except Exception as e:
            print(f"  {balance_type}: not available ({type(e).__name__})")

    print("\nNo funding/earn balance found")
    return {'total': 0}


def main():
    """Main test function."""
    print("\n" + "="*60)
    print("   MEXC BALANCE TEST SCRIPT")
    print("   " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("="*60)

    # Create client
    exchange = create_mexc_client()
    print(f"\nConnected to MEXC (CCXT version: {ccxt.__version__})")

    # Run tests
    market_types = test_market_types(exchange)
    spot_result = test_spot_balance(exchange)
    swap_result = test_swap_balance(exchange)
    positions_result = test_positions(exchange)
    funding_result = test_funding_balance(exchange)
    trades_result = test_recent_trades(exchange)

    # Summary
    print_section("SUMMARY - TOTAL ACCOUNT VALUE")

    spot_value = spot_result.get('usdt_equiv', 0)
    swap_value = swap_result.get('total', 0)
    funding_value = funding_result.get('total', 0)
    unrealized_pnl = positions_result.get('unrealized_pnl', 0)

    print(f"\n  Spot Stablecoins:     {format_currency(spot_value):>15} USD")
    print(f"  Swap/Futures Equity:  {format_currency(swap_value):>15} USD")
    print(f"  Funding/Earn:         {format_currency(funding_value):>15} USD")
    print(f"  Unrealized PnL:       {format_currency(unrealized_pnl):>+15} USD")
    print(f"  {'-'*40}")

    # Check if spot and swap might be sharing the same pool
    if abs(spot_value - swap_value) < 1.0 and spot_value > 0:
        print(f"\n  ⚠️  WARNING: Spot and Swap balances are nearly identical!")
        print(f"      This suggests MEXC unified margin mode is active.")
        print(f"      The balances may be shared (not additive).")
        print(f"\n  >>> ESTIMATED TOTAL: {format_currency(swap_value)} USD")
        print(f"      (Using swap balance to avoid double-counting)")
    else:
        total = spot_value + swap_value + funding_value
        print(f"\n  >>> TOTAL EQUITY: {format_currency(total)} USD")

    print_section("INTEGRATION DIAGNOSIS")

    print(f"""
Current integration behavior (snapshot-breakdown.ts):
  - MEXC is in UNIFIED_MARGIN_EXCHANGES
  - Filters OUT: spot, future, margin
  - Only counts: swap

Detected market types: {', '.join(market_types)}
Filtered types (by current code): {', '.join([t for t in market_types if t not in ['spot', 'future', 'margin']])}

If spot and swap show the SAME balance:
  ✅ Current filtering is CORRECT (avoids double-counting)

If spot and swap show DIFFERENT balances:
  ❌ Current filtering may be WRONG
  → Spot assets might not be counted!
  → Consider removing 'mexc' from UNIFIED_MARGIN_EXCHANGES

Spot non-stablecoin assets found: {len([a for a in spot_result.get('assets', []) if a['currency'] not in ['USDT', 'USDC', 'USD']])}
  (These need conversion to USD for accurate total)
""")


if __name__ == '__main__':
    main()
