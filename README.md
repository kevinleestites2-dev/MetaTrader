# MetaTrader — Pantheon Trading Engine

The most advanced multi-strategy crypto trading bot in the Pantheon. Connects to 10+ markets, runs 19 trading strategies across 3 tiers, and adapts in real-time using SAFLA market regime detection.

---

## Architecture

```
CMC Signal Scan → SAFLA Regime Detection → Strategy Selection → Risk Check → Security Check → Execute → Log → Telegram Report
```

---

## Strategy Library

### Tier 1 — Most Reliable
- Funding Rate Arbitrage
- Statistical Arbitrage
- Grid Trading
- VWAP Reversion
- Order Flow Imbalance
- Delta Divergence

### Tier 2 — High Upside
- Momentum Breakout
- Liquidity Sweep / Stop Hunt Detection
- On-Chain Whale Flow
- Open Interest Spike
- Liquidation Cascade Hunting
- Basis Trading
- Volatility Breakout

### Tier 3 — Advanced
- Cross-Exchange Arbitrage
- Sentiment + Price Confluence
- MEV/Sandwich Detection
- Token Unlock Calendar Trading

---

## Markets Connected

| Market | Type | Auth |
|--------|------|------|
| Polymarket | Prediction Markets | CLOB SDK |
| Kalshi | Prediction Markets | Key + Private Key |
| Kraken | Crypto Spot | Public REST |
| OKX | Crypto / Perps | Public REST |
| Deribit | Options / Derivatives | Public REST |
| Hyperliquid | DEX Perps | FinceptTerminal |
| CoinGecko | Market Data | Free |
| Binance | Price / Volume | Public REST |
| Fear & Greed | Sentiment | Free |
| DexScreener | DEX Data | Free |
| CoinMarketCap | Volume / Rankings | API Key |

---

## Security Stack (5 Layers)

1. **KeyVault** — Fernet-encrypted key storage, never touches disk after startup
2. **TradeValidator** — pair whitelist, $500 position cap, $200 daily loss limit
3. **SecureRequester** — HTTPS-only, HMAC-SHA256 signing, rate limiter
4. **TamperEvidentLog** — SQLite + SHA-256 checksums, Telegram alerts on every event
5. **Governor** — $2,000 daily volume ceiling, kill switch via Telegram `/kill`

---

## Risk Management

- Kelly-inspired position sizing
- ATR/volatility-scaled stop losses
- Minimum 2:1 R:R ratio gate
- 5% daily drawdown pause / 15% total halt
- 3 consecutive losses → 60-minute cooldown
- Per-asset exposure caps (Crypto 40%, Prediction Markets 20%)

---

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your API keys

# Run
python metatrader.py
```

---

## Required Keys (.env)

```
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
CMC_API_KEY=
POLYMARKET_API_KEY=
POLYMARKET_API_SECRET=
POLYMARKET_API_PASSPHRASE=
KALSHI_KEY_ID=
KALSHI_PRIVATE_KEY_PATH=
METATRADER_MASTER_KEY=
```

---

## Telegram Commands

| Command | Action |
|---------|--------|
| `/kill` | Emergency stop — halts all trading immediately |
| `/status` | Current P&L, open positions, risk stats |
| `/pause` | Pause trading loop |
| `/resume` | Resume trading loop |

---

## Built On

- [FinceptTerminal](https://github.com/Fincept-Corporation/FinceptTerminal) — exchange connectors + data feeds
- [CloakPrime](https://github.com/kevinleestites2-dev/CloakPrime) — stealth signal obfuscation
- SAFLA v2.0 — self-adaptive market regime detection

---

*Part of the Pantheon. Built by the Forgemaster.*
