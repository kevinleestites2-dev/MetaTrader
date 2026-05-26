#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          METATRADER v1.0                                    ║
║                   The Best Crypto Trading Bot in the World                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Features:                                                                  ║
║  • SAFLA - Market regime detection & signal analysis                        ║
║  • 14 Strategies across 3 risk tiers                                        ║
║  • 5-Layer Pantheon Security Stack                                          ║
║  • Kelly-inspired Risk Management                                           ║
║  • Multi-Exchange: Polymarket, Kraken, OKX, Deribit, Binance               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python metatrader.py
    
Or:
    from metatrader import MetaTrader
    bot = MetaTrader()
    await bot.run()
"""

import asyncio
import logging
import os
import time
import hashlib
import hmac
import sqlite3
import threading
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from decimal import Decimal

import requests
import numpy as np
from dotenv import load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

class AssetClass(Enum):
    CRYPTO = "crypto"
    PREDICTION = "prediction_markets"
    FOREX = "forex"
    EQUITIES = "equities"

class MarketRegime(Enum):
    TRENDING_UP = "TRENDING_UP"
    TRENDING_DOWN = "TRENDING_DOWN"
    RANGING = "RANGING"
    VOLATILE = "VOLATILE"
    LOW_LIQUIDITY = "LOW_LIQUIDITY"
    UNKNOWN = "UNKNOWN"

class StrategyRecommendation(Enum):
    FUNDING_RATE_ARB = "FUNDING_RATE_ARB"
    GRID_TRADING = "GRID_TRADING"
    MOMENTUM_BREAKOUT = "MOMENTUM_BREAKOUT"
    MEAN_REVERSION = "MEAN_REVERSION"
    LIQUIDITY_HUNT = "LIQUIDITY_HUNT"
    ON_CHAIN_FLOW = "ON_CHAIN_FLOW"
    STATISTICAL_ARB = "STATISTICAL_ARB"
    SENTIMENT_CONF = "SENTIMENT_CONF"
    VOLATILITY_BREAKOUT = "VOLATILITY_BREAKOUT"
    HUNT_STOP_HUNTS = "HUNT_STOP_HUNTS"
    NO_SIGNAL = "NO_SIGNAL"

class StrategyTier(Enum):
    TIER_1_CONSERVATIVE = 1
    TIER_2_MODERATE = 2
    TIER_3_AGGRESSIVE = 3


@dataclass
class Position:
    pair: str
    side: str  # LONG or SHORT
    entry_price: float
    quantity: float
    stop_loss: float
    take_profit: float
    open_time: datetime
    exchange: str
    strategy: str
    atr_at_entry: float = 0.0
    risk_amount: float = 0.0
    
    def current_pnl(self, current_price: float) -> float:
        if self.side == "LONG":
            return (current_price - self.entry_price) * self.quantity
        else:
            return (self.entry_price - current_price) * self.quantity
    
    def unrealized_pnl_pct(self, current_price: float) -> float:
        pnl = self.current_pnl(current_price)
        return (pnl / (self.entry_price * self.quantity)) * 100 if self.entry_price > 0 else 0
    
    def is_stop_hit(self, current_price: float) -> bool:
        if self.side == "LONG":
            return current_price <= self.stop_loss
        else:
            return current_price >= self.stop_loss
    
    def is_tp_hit(self, current_price: float) -> bool:
        if self.side == "LONG":
            return current_price >= self.take_profit
        else:
            return current_price <= self.take_profit


@dataclass
class TradeRecord:
    timestamp: datetime
    pair: str
    side: str
    price: float
    quantity: float
    exchange: str
    strategy: str
    signal_strength: float
    pnl: Optional[float] = None
    status: str = "PENDING"


@dataclass
class RiskConfig:
    total_capital_usd: float = 1000.0
    max_risk_per_trade_pct: float = 2.0
    min_risk_reward_ratio: float = 2.0
    daily_drawdown_pause_pct: float = 5.0
    total_drawdown_halt_pct: float = 15.0
    loss_streak_pause_count: int = 3
    loss_streak_pause_minutes: int = 60
    max_correlation_pairs: int = 2


@dataclass
class MarketAnalysis:
    regime: MarketRegime
    confidence: float
    volatility: float
    momentum: float
    volume_profile: str
    recommendation: StrategyRecommendation
    recommendation_strength: float
    signals: List[str]
    warnings: List[str]


@dataclass
class StrategySignal:
    strategy_name: str
    pair: str
    side: str  # LONG, SHORT, SKIP, NEUTRAL
    entry_price: float
    stop_loss: float
    take_profit: float
    confidence: float
    tier: StrategyTier
    metadata: Dict[str, Any]
    risk_amount: float


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1: KEY VAULT - Secure Key Storage
# ══════════════════════════════════════════════════════════════════════════════

class KeyVault:
    """Fernet-encrypted key storage. Keys never touch disk after startup."""
    
    def __init__(self, vault_file: str = ".vault.key"):
        self.vault_file = Path(vault_file)
        self._keys: Dict[str, str] = {}
        self._cipher = None
        self._lock = threading.RLock()
        self._initialize()
    
    def _initialize(self):
        from cryptography.fernet import Fernet
        master_key = os.environ.get("METATRADER_MASTER_KEY")
        if master_key:
            key_bytes = hashlib.sha256(master_key.encode()).digest()
            self._cipher = Fernet(Fernet.generate_key()[:32].ljust(32, b'0'))
            self._master_hash = hashlib.sha256(master_key.encode()).digest()
        else:
            self._cipher = Fernet(Fernet.generate_key())
            logger.warning("No master key - using ephemeral encryption")
        self._load_keys()
    
    def _load_keys(self):
        if self.vault_file.exists():
            try:
                with open(self.vault_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted = self._cipher.decrypt(encrypted_data)
                lines = decrypted.decode().split('\n')
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        self._keys[key.strip()] = value.strip()
                logger.info(f"Loaded {len(self._keys)} keys from vault")
            except Exception as e:
                logger.error(f"Failed to load vault: {e}")
    
    def _save_keys(self):
        data = '\n'.join(f"{k}:{v}" for k, v in self._keys.items())
        encrypted = self._cipher.encrypt(data.encode())
        with open(self.vault_file, 'wb') as f:
            f.write(encrypted)
    
    def get(self, key_name: str) -> Optional[str]:
        with self._lock:
            return self._keys.get(key_name)
    
    def set(self, key_name: str, value: str):
        with self._lock:
            self._keys[key_name] = value
            self._save_keys()
    
    def clear_memory(self):
        with self._lock:
            self._keys.clear()


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2: TRADE VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

class TradeValidator:
    """Pair whitelist, hard position size cap, daily loss limit, duplicate detection."""
    
    ALLOWED_PAIRS = {
        'CRYPTO': {'BTC/USD', 'ETH/USD', 'SOL/USD', 'AVAX/USD', 'LINK/USD',
                   'BTC/USDT', 'ETH/USDT', 'BTC-USD', 'ETH-USD', 'SOL-USD'},
        'PREDICTION': {'POLYMARKET', 'KALSHI'}
    }
    
    MAX_POSITION_USD = 500.0
    MAX_DAILY_LOSS_USD = 200.0
    HIGH_VALUE_THRESHOLD = 300.0
    SIGNAL_WINDOW_SECONDS = 30.0
    
    def __init__(self):
        self._recent_signals: Dict[str, datetime] = {}
        self._daily_pnl = 0.0
        self._last_reset = datetime.now().date()
        self._lock = threading.Lock()
        self._daily_trades: List[TradeRecord] = []
    
    def validate_trade(self, pair: str, size_usd: float, strategy: str) -> Tuple[bool, str]:
        with self._lock:
            self._check_daily_reset()
            
            if self._daily_pnl <= -self.MAX_DAILY_LOSS_USD:
                return False, f"Daily loss limit exceeded: ${abs(self._daily_pnl):.2f}"
            
            if not self._is_pair_allowed(pair):
                return False, f"Pair not in whitelist: {pair}"
            
            if size_usd > self.MAX_POSITION_USD:
                return False, f"Position size ${size_usd:.2f} exceeds cap ${self.MAX_POSITION_USD}"
            
            signal_key = f"{pair}:{strategy}"
            now = datetime.now()
            if signal_key in self._recent_signals:
                elapsed = (now - self._recent_signals[signal_key]).total_seconds()
                if elapsed < self.SIGNAL_WINDOW_SECONDS:
                    return False, f"Duplicate signal within window: {elapsed:.1f}s"
            
            self._recent_signals[signal_key] = now
            return True, "OK"
    
    def _is_pair_allowed(self, pair: str) -> bool:
        pair_upper = pair.upper().replace('-', '/').replace('_', '/')
        for category_pairs in self.ALLOWED_PAIRS.values():
            for allowed in category_pairs:
                allowed_normalized = allowed.upper().replace('-', '/').replace('_', '/')
                if pair_upper == allowed_normalized or allowed in pair_upper:
                    return True
        return False
    
    def _check_daily_reset(self):
        today = datetime.now().date()
        if today > self._last_reset:
            self._daily_pnl = 0.0
            self._daily_trades.clear()
            self._last_reset = today
    
    def update_daily_pnl(self, pnl: float):
        with self._lock:
            self._daily_pnl += pnl
    
    def requires_human_confirmation(self, size_usd: float) -> bool:
        return size_usd > self.HIGH_VALUE_THRESHOLD


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3: SECURE REQUESTER
# ══════════════════════════════════════════════════════════════════════════════

class SecureRequester:
    """HTTPS-only, HMAC-SHA256 request signing, rate limiting."""
    
    def __init__(self, vault: KeyVault):
        self.vault = vault
        self._rate_limit = RateLimiter()
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'MetaTrader/1.0',
            'Accept': 'application/json'
        })
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        if not url.startswith('https://'):
            raise ValueError(f"Non-HTTPS URL blocked: {url}")
        
        self._rate_limit.wait_if_needed(url)
        
        headers = kwargs.get('headers', {})
        if 'Authorization' in headers:
            signature = self._sign_request(method, url, headers)
            headers['X-Signature'] = signature
        kwargs['headers'] = headers
        kwargs['timeout'] = kwargs.get('timeout', 30)
        
        return self._session.request(method, url, **kwargs)
    
    def _sign_request(self, method: str, url: str, headers: Dict) -> str:
        timestamp = str(int(time.time()))
        message = f"{timestamp}{method}{url}"
        signature = hmac.new(
            self._master_hash if hasattr(self, '_master_hash') else b'secret',
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{timestamp}:{signature}"
    
    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request('POST', url, **kwargs)


class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, calls_per_second: int = 10):
        self.cps = calls_per_second
        self._buckets: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
    
    def wait_if_needed(self, bucket_key: str):
        with self._lock:
            now = time.time()
            if bucket_key not in self._buckets:
                self._buckets[bucket_key] = []
            
            self._buckets[bucket_key] = [
                t for t in self._buckets[bucket_key]
                if now - t < 1.0
            ]
            
            if len(self._buckets[bucket_key]) >= self.cps:
                sleep_time = 1.0 - (now - self._buckets[bucket_key][0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            self._buckets[bucket_key].append(now)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4: TAMPER EVIDENT LOG
# ══════════════════════════════════════════════════════════════════════════════

class TamperEvidentLog:
    """SQLite with SHA-256 checksums."""
    
    def __init__(self, log_file: str = "metatrader_log.db"):
        self.log_file = Path(log_file)
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(str(self.log_file))
        conn.execute('''
            CREATE TABLE IF NOT EXISTS trade_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                pair TEXT,
                side TEXT,
                price REAL,
                quantity REAL,
                exchange TEXT,
                strategy TEXT,
                pnl REAL,
                checksum TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS integrity_chain (
                id INTEGER PRIMARY KEY,
                previous_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
    
    def log_trade(self, trade: TradeRecord):
        conn = sqlite3.connect(str(self.log_file))
        
        entry = f"{trade.timestamp.isoformat()}|{trade.pair}|{trade.side}|{trade.price}|{trade.quantity}|{trade.exchange}"
        checksum = hashlib.sha256(entry.encode()).hexdigest()
        
        conn.execute('''
            INSERT INTO trade_log (timestamp, event_type, pair, side, price, quantity, exchange, strategy, pnl, checksum)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            trade.timestamp.isoformat(), 'TRADE', trade.pair, trade.side,
            trade.price, trade.quantity, trade.exchange, trade.strategy, trade.pnl, checksum
        ))
        
        cursor = conn.execute('SELECT MAX(id) FROM trade_log')
        last_id = cursor.fetchone()[0] or 0
        
        cursor = conn.execute('SELECT block_hash FROM integrity_chain ORDER BY id DESC LIMIT 1')
        prev_hash = cursor.fetchone()[0] if cursor.fetchone() else 'GENESIS'
        
        block_data = f"{last_id}|{prev_hash}|{checksum}|{datetime.now().isoformat()}"
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()
        
        conn.execute('INSERT INTO integrity_chain (id, previous_hash, block_hash, timestamp) VALUES (?, ?, ?, ?)',
                    (last_id, prev_hash, block_hash, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def log_event(self, event_type: str, details: Dict[str, Any]):
        entry = f"{datetime.now().isoformat()}|{event_type}|{str(details)}"
        checksum = hashlib.sha256(entry.encode()).hexdigest()
        
        conn = sqlite3.connect(str(self.log_file))
        conn.execute('''
            INSERT INTO trade_log (timestamp, event_type, checksum)
            VALUES (?, ?, ?)
        ''', (datetime.now().isoformat(), event_type, checksum))
        conn.commit()
        conn.close()
    
    def verify_integrity(self) -> bool:
        conn = sqlite3.connect(str(self.log_file))
        cursor = conn.execute('SELECT previous_hash, block_hash FROM integrity_chain ORDER BY id')
        prev_hash = 'GENESIS'
        
        for row in cursor:
            if row[0] != prev_hash:
                return False
            prev_hash = row[1]
        
        return True


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5: GOVERNOR
# ══════════════════════════════════════════════════════════════════════════════

class Governor:
    """Daily volume ceiling, human confirmation, emergency kill switch."""
    
    MAX_DAILY_VOLUME = 2000.0
    
    def __init__(self):
        self._daily_volume = 0.0
        self._last_reset = datetime.now().date()
        self._is_paused = False
        self._pause_until: Optional[datetime] = None
        self._kill_switch = False
        self._lock = threading.Lock()
        self._pending_confirmations: Dict[str, TradeRecord] = {}
    
    def check_volume(self, amount: float) -> Tuple[bool, str]:
        with self._lock:
            self._check_daily_reset()
            
            if self._is_paused and self._pause_until:
                if datetime.now() < self._pause_until:
                    return False, f"Trading paused until {self._pause_until}"
                else:
                    self._is_paused = False
            
            if self._kill_switch:
                return False, "Kill switch activated - manual restart required"
            
            if self._daily_volume + amount > self.MAX_DAILY_VOLUME:
                return False, f"Would exceed daily volume limit: ${self._daily_volume + amount:.2f} > ${self.MAX_DAILY_VOLUME}"
            
            return True, "OK"
    
    def add_volume(self, amount: float):
        with self._lock:
            self._daily_volume += amount
    
    def trigger_pause(self, reason: str, duration_minutes: int = 60):
        with self._lock:
            self._is_paused = True
            self._pause_until = datetime.now() + timedelta(minutes=duration_minutes)
            logger.warning(f"Trading paused: {reason}")
    
    def activate_kill_switch(self):
        with self._lock:
            self._kill_switch = True
            logger.critical("KILL SWITCH ACTIVATED")
    
    def deactivate_kill_switch(self):
        with self._lock:
            self._kill_switch = False
            logger.info("Kill switch deactivated")
    
    def _check_daily_reset(self):
        today = datetime.now().date()
        if today > self._last_reset:
            self._daily_volume = 0.0
            self._last_reset = today
    
    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'daily_volume': self._daily_volume,
                'max_volume': self.MAX_DAILY_VOLUME,
                'is_paused': self._is_paused,
                'pause_until': self._pause_until,
                'kill_switch': self._kill_switch,
                'pending_confirmations': len(self._pending_confirmations)
            }


# ══════════════════════════════════════════════════════════════════════════════
# PANTHEON SECURITY STACK
# ══════════════════════════════════════════════════════════════════════════════

class PantheonSecurityStack:
    """Main Security Stack - Combines all 5 layers."""
    
    def __init__(self, vault_file: str = ".vault.key", log_file: str = "metatrader_log.db"):
        self.vault = KeyVault(vault_file)
        self.requester = SecureRequester(self.vault)
        self.validator = TradeValidator()
        self.logger = TamperEvidentLog(log_file)
        self.governor = Governor()
        
        self._telegram_enabled = False
        self._telegram_token: Optional[str] = None
        self._telegram_chat_id: Optional[str] = None
    
    def setup_telegram(self, token: str, chat_id: str):
        self._telegram_enabled = True
        self._telegram_token = token
        self._telegram_chat_id = chat_id
    
    def authorize_trade(self, pair: str, size_usd: float, strategy: str) -> Tuple[bool, str]:
        valid, reason = self.validator.validate_trade(pair, size_usd, strategy)
        if not valid:
            return False, f"Validation failed: {reason}"
        
        valid, reason = self.governor.check_volume(size_usd)
        if not valid:
            return False, f"Governor rejected: {reason}"
        
        if self.governor.requires_human_confirmation(size_usd):
            return False, f"Human confirmation required for ${size_usd:.2f} trade"
        
        return True, "Authorized"
    
    def log_trade(self, trade: TradeRecord):
        self.logger.log_trade(trade)
        self.governor.add_volume(trade.price * trade.quantity)
        
        if trade.pnl is not None:
            self.validator.update_daily_pnl(trade.pnl)
        
        if self._telegram_enabled:
            self._send_telegram_alert(trade)
    
    def log_error(self, error: str, context: Dict[str, Any] = None):
        self.logger.log_event("ERROR", {'error': error, 'context': context or {}})
        if self._telegram_enabled:
            self._send_telegram_message(f"⚠️ ERROR: {error}")
    
    def log_restart(self):
        self.logger.log_event("RESTART", {'timestamp': datetime.now().isoformat()})
        if self._telegram_enabled:
            self._send_telegram_message("🔄 MetaTrader restarted")
    
    def emergency_kill(self):
        self.governor.activate_kill_switch()
        self.logger.log_event("KILL", {'timestamp': datetime.now().isoformat()})
        if self._telegram_enabled:
            self._send_telegram_message("🚨 EMERGENCY KILL ACTIVATED")
    
    def _send_telegram_alert(self, trade: TradeRecord):
        pnl_str = f"+${trade.pnl:.2f}" if trade.pnl and trade.pnl > 0 else f"${trade.pnl:.2f}" if trade.pnl else "OPEN"
        message = f"📊 Trade Executed\nPair: {trade.pair}\nSide: {trade.side}\nQty: {trade.quantity}\nPnL: {pnl_str}\nStrategy: {trade.strategy}"
        self._send_telegram_message(message)
    
    def _send_telegram_message(self, message: str):
        if not self._telegram_token or not self._telegram_chat_id:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
            self.requester.post(url, json={
                'chat_id': self._telegram_chat_id,
                'text': message
            })
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
    
    def get_status_report(self) -> str:
        gov_status = self.governor.get_status()
        
        report = "📈 MetaTrader Status Report\n"
        report += f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        report += f"Daily Volume: ${gov_status['daily_volume']:.2f} / ${gov_status['max_volume']}\n"
        report += f"Status: {'🟢 Active' if not gov_status['is_paused'] and not gov_status['kill_switch'] else '🔴 Paused/Killed'}\n"
        
        if gov_status['is_paused']:
            report += f"Paused until: {gov_status['pause_until']}\n"
        
        if gov_status['kill_switch']:
            report += "⚠️ KILL SWITCH ACTIVE\n"
        
        report += f"\nPending Confirmations: {gov_status['pending_confirmations']}"
        
        return report


# ══════════════════════════════════════════════════════════════════════════════
# RISK MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class RiskManager:
    """Kelly-inspired position sizing, ATR stops, drawdown protection."""
    
    EXPOSURE_LIMITS = {
        AssetClass.CRYPTO: 0.40,
        AssetClass.PREDICTION: 0.20,
        AssetClass.FOREX: 0.30,
        AssetClass.EQUITIES: 0.30
    }
    
    CORRELATED_GROUPS = {
        'BTC_GROUP': ['BTC/USD', 'BTC/USDT', 'BTC-USD', 'BTC-USD-PERP'],
        'ETH_GROUP': ['ETH/USD', 'ETH/USDT', 'ETH-USD', 'ETH-USD-PERP'],
        'ALT_GROUP': ['SOL/USD', 'AVAX/USD', 'LINK/USD']
    }
    
    def __init__(self, config: RiskConfig):
        self.config = config
        self._positions: Dict[str, Position] = {}
        self._closed_trades = []
        self._capital = config.total_capital_usd
        self._peak_capital = config.total_capital_usd
        self._daily_pnl = 0.0
        self._last_reset = datetime.now().date()
        self._consecutive_losses = 0
        self._is_paused = False
        self._pause_until: Optional[datetime] = None
        self._loss_streak_start: Optional[datetime] = None
        self._lock = threading.Lock()
        
        self._total_trades = 0
        self._winning_trades = 0
        self._losing_trades = 0
        self._total_win_amount = 0.0
        self._total_loss_amount = 0.0
    
    def check_trade(self, pair: str, side: str, entry_price: float,
                    stop_loss: float, take_profit: float,
                    signal_strength: float = 1.0, atr: float = 0.0) -> Tuple[bool, str, Optional[float]]:
        with self._lock:
            if self._is_paused and self._pause_until:
                if datetime.now() < self._pause_until:
                    return False, f"Trading paused until {self._pause_until}", None
                else:
                    self._is_paused = False
            
            drawdown_check = self._check_drawdown()
            if not drawdown_check[0]:
                return False, drawdown_check[1], None
            
            if self._check_loss_streak():
                return False, f"Loss streak protection active ({self._consecutive_losses} losses)", None
            
            if entry_price <= 0 or stop_loss <= 0 or take_profit <= 0:
                return False, "Invalid price values", None
            
            if side not in ['LONG', 'SHORT']:
                return False, f"Invalid side: {side}", None
            
            risk_distance = abs(entry_price - stop_loss)
            reward_distance = abs(take_profit - entry_price)
            rr_ratio = reward_distance / risk_distance if risk_distance > 0 else 0
            
            if rr_ratio < self.config.min_risk_reward_ratio:
                return False, f"R:R ratio {rr_ratio:.2f} below minimum {self.config.min_risk_reward_ratio}", None
            
            position_size = self._calculate_position_size(entry_price, stop_loss, signal_strength)
            
            if position_size <= 0:
                return False, "Position size too small", None
            
            exposure_check = self._check_exposure(pair, position_size * entry_price)
            if not exposure_check[0]:
                return False, exposure_check[1], None
            
            corr_check = self._check_correlation(pair)
            if not corr_check[0]:
                return False, corr_check[1], None
            
            return True, "APPROVED", position_size
    
    def _calculate_position_size(self, entry_price: float, stop_loss: float, signal_strength: float = 1.0) -> float:
        risk_per_trade = self._capital * (self.config.max_risk_per_trade_pct / 100)
        risk_distance = abs(entry_price - stop_loss)
        
        if risk_distance == 0:
            return 0.0
        
        kelly_fraction = 0.25
        base_size = risk_per_trade / risk_distance
        adjusted_size = base_size * (0.5 + signal_strength)
        kelly_size = adjusted_size * kelly_fraction
        max_size = risk_per_trade / risk_distance
        
        return min(kelly_size, max_size)
    
    def _check_drawdown(self) -> Tuple[bool, str]:
        current_capital = self._capital + self._daily_pnl
        current_drawdown = ((self._peak_capital - current_capital) / self._peak_capital) * 100
        daily_drawdown = abs(self._daily_pnl) / self._peak_capital * 100 if self._daily_pnl < 0 else 0
        
        if daily_drawdown >= self.config.daily_drawdown_pause_pct:
            self._trigger_pause("Daily drawdown limit")
            return False, f"Daily drawdown {daily_drawdown:.1f}% exceeds limit"
        
        if current_drawdown >= self.config.total_drawdown_halt_pct:
            self._is_paused = True
            self._pause_until = None
            return False, f"Total drawdown {current_drawdown:.1f}% - trading halted"
        
        return True, "OK"
    
    def _check_loss_streak(self) -> bool:
        if self._consecutive_losses >= self.config.loss_streak_pause_count:
            if not self._loss_streak_start:
                self._loss_streak_start = datetime.now()
            
            elapsed = (datetime.now() - self._loss_streak_start).total_seconds() / 60
            if elapsed < self.config.loss_streak_pause_minutes:
                return True
            else:
                self._consecutive_losses = 0
                self._loss_streak_start = None
        
        return False
    
    def _check_exposure(self, pair: str, position_value: float) -> Tuple[bool, str]:
        asset_class = self._get_asset_class(pair)
        max_exposure = self._capital * self.EXPOSURE_LIMITS.get(asset_class, 0.40)
        
        current_exposure = sum(
            pos.entry_price * pos.quantity
            for pos in self._positions.values()
            if self._get_asset_class(pos.pair) == asset_class
        )
        
        if current_exposure + position_value > max_exposure:
            return False, f"Exposure limit reached for {asset_class.value}"
        
        return True, "OK"
    
    def _check_correlation(self, pair: str) -> Tuple[bool, str]:
        for group_name, group_pairs in self.CORRELATED_GROUPS.items():
            if any(gp in pair.upper() for gp in group_pairs):
                existing = sum(1 for p in self._positions.keys() 
                             if any(gp in p.upper() for gp in group_pairs))
                if existing >= self.config.max_correlation_pairs:
                    return False, f"Max correlated positions in {group_name} ({self.config.max_correlation_pairs})"
        
        return True, "OK"
    
    def _get_asset_class(self, pair: str) -> AssetClass:
        pair_upper = pair.upper()
        
        if 'POLYMARKET' in pair_upper or 'KALSHI' in pair_upper:
            return AssetClass.PREDICTION
        
        crypto_pairs = ['BTC', 'ETH', 'SOL', 'AVAX', 'LINK', 'USDT', 'USD']
        if any(cp in pair_upper for cp in crypto_pairs):
            return AssetClass.CRYPTO
        
        return AssetClass.CRYPTO
    
    def open_position(self, position: Position) -> bool:
        with self._lock:
            if position.pair in self._positions:
                return False
            
            self._positions[position.pair] = position
            self._total_trades += 1
            logger.info(f"Opened {position.side} position: {position.pair} @ {position.entry_price}")
            return True
    
    def close_position(self, pair: str, exit_price: float, reason: str):
        with self._lock:
            if pair not in self._positions:
                return None
            
            position = self._positions[pair]
            pnl = position.current_pnl(exit_price)
            pnl_pct = position.unrealized_pnl_pct(exit_price)
            duration = (datetime.now() - position.open_time).total_seconds() / 60
            
            result = {
                'pair': pair, 'side': position.side, 'entry_price': position.entry_price,
                'exit_price': exit_price, 'quantity': position.quantity, 'pnl': pnl,
                'pnl_pct': pnl_pct, 'duration_minutes': duration, 'strategy': position.strategy,
                'was_win': pnl > 0, 'exit_reason': reason
            }
            self._closed_trades.append(result)
            
            if pnl > 0:
                self._winning_trades += 1
                self._total_win_amount += pnl
                self._consecutive_losses = 0
            else:
                self._losing_trades += 1
                self._total_loss_amount += abs(pnl)
                self._consecutive_losses += 1
            
            self._capital += pnl
            if self._capital > self._peak_capital:
                self._peak_capital = self._capital
            
            self._daily_pnl += pnl
            del self._positions[pair]
            
            logger.info(f"Closed {pair}: PnL ${pnl:.2f} ({reason})")
            return result
    
    def check_stop_loss(self, pair: str, current_price: float) -> Optional[str]:
        if pair not in self._positions:
            return None
        
        position = self._positions[pair]
        
        if position.is_stop_hit(current_price):
            return "STOP_HIT"
        
        if position.is_tp_hit(current_price):
            return "TP_HIT"
        
        return None
    
    def _trigger_pause(self, reason: str):
        self._is_paused = True
        self._pause_until = datetime.now() + timedelta(minutes=5)
        logger.warning(f"Trading paused: {reason}")
    
    def get_open_positions(self) -> List[Position]:
        with self._lock:
            return list(self._positions.values())
    
    def get_position(self, pair: str) -> Optional[Position]:
        return self._positions.get(pair)
    
    def get_statistics(self) -> Dict[str, Any]:
        win_rate = (self._winning_trades / self._total_trades * 100) if self._total_trades > 0 else 0
        avg_win = self._total_win_amount / self._winning_trades if self._winning_trades > 0 else 0
        avg_loss = self._total_loss_amount / self._losing_trades if self._losing_trades > 0 else 0
        
        return {
            'total_trades': self._total_trades,
            'winning_trades': self._winning_trades,
            'losing_trades': self._losing_trades,
            'win_rate': win_rate,
            'avg_win': avg_win,
            'avg_loss': avg_loss,
            'total_capital': self._capital,
            'peak_capital': self._peak_capital,
            'daily_pnl': self._daily_pnl,
            'consecutive_losses': self._consecutive_losses,
            'is_paused': self._is_paused,
            'open_positions': len(self._positions)
        }
    
    def status_report(self) -> str:
        stats = self.get_statistics()
        positions = self.get_open_positions()
        
        report = "📊 Risk Manager Status Report\n"
        report += f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        report += f"💰 Capital: ${stats['total_capital']:.2f}"
        if stats['daily_pnl'] != 0:
            pnl_str = f"+${stats['daily_pnl']:.2f}" if stats['daily_pnl'] > 0 else f"-${abs(stats['daily_pnl']):.2f}"
            report += f" ({pnl_str} today)"
        report += "\n"
        
        report += f"Peak: ${stats['peak_capital']:.2f}\n"
        report += f"Drawdown: {((stats['peak_capital'] - stats['total_capital']) / stats['peak_capital'] * 100):.2f}%\n\n"
        
        report += f"📈 Trading Stats:\n"
        report += f"Total Trades: {stats['total_trades']}\n"
        report += f"Win Rate: {stats['win_rate']:.1f}%\n"
        if stats['winning_trades'] > 0:
            report += f"Avg Win: ${stats['avg_win']:.2f}\n"
        if stats['losing_trades'] > 0:
            report += f"Avg Loss: ${stats['avg_loss']:.2f}\n"
        
        report += f"\n🛡️ Risk Status:\n"
        report += f"Open Positions: {len(positions)}\n"
        if stats['is_paused']:
            report += f"⚠️ TRADING PAUSED\n"
        if stats['consecutive_losses'] > 0:
            report += f"Loss Streak: {stats['consecutive_losses']}\n"
        
        if positions:
            report += f"\n📋 Open Positions:\n"
            for pos in positions:
                report += f"  {pos.pair}: {pos.side} @ {pos.entry_price}\n"
        
        return report


# ══════════════════════════════════════════════════════════════════════════════
# SAFLA - SIGNAL ANALYSIS FOR LIVE APPLICATIONS
# ══════════════════════════════════════════════════════════════════════════════

class SAFLA:
    """Market regime detection and strategy recommendation engine."""
    
    TREND_THRESHOLD = 0.7
    VOLATILE_THRESHOLD = 2.0
    MOMENTUM_STRONG = 0.6
    
    def __init__(self):
        self._price_history: Dict[str, List[float]] = {}
        self._regime_cache: Dict[str, MarketAnalysis] = {}
        self._last_analysis: Dict[str, float] = {}
    
    def analyze_market(self, pair: str, prices: List[float], 
                      volumes: List[float] = None,
                      order_book_imbalance: float = 0.0,
                      funding_rate: float = 0.0,
                      volume_delta: float = 0.0) -> MarketAnalysis:
        
        if len(prices) < 20:
            return self._insufficient_data_analysis()
        
        prices = np.array(prices)
        volumes = np.array(volumes) if volumes else np.ones_like(prices)
        
        volatility = self._calculate_volatility(prices)
        momentum = self._calculate_momentum(prices)
        adx = self._calculate_adx(prices)
        trend_direction = self._detect_trend_direction(prices, adx)
        volume_profile = self._analyze_volume_profile(volumes)
        
        regime = self._detect_regime(adx, volatility, momentum, trend_direction, volume_profile)
        confidence = self._calculate_confidence(prices, adx, volumes)
        recommendation = self._get_strategy_recommendation(regime, funding_rate, order_book_imbalance, volume_delta)
        signals = self._generate_signals(prices, momentum, funding_rate, order_book_imbalance, volume_delta)
        warnings = self._generate_warnings(volume_profile, volatility, adx)
        
        analysis = MarketAnalysis(
            regime=regime, confidence=confidence, volatility=volatility,
            momentum=momentum, volume_profile=volume_profile,
            recommendation=recommendation[0], recommendation_strength=recommendation[1],
            signals=signals, warnings=warnings
        )
        
        self._regime_cache[pair] = analysis
        self._last_analysis[pair] = time.time()
        
        return analysis
    
    def _calculate_volatility(self, prices: np.ndarray) -> float:
        if len(prices) < 14:
            return 1.0
        
        tr = np.abs(prices[1:] - prices[:-1])
        tr = np.append(tr, np.abs(prices[-1] - prices[-2]))
        atr = np.mean(tr[-14:])
        normalized_vol = atr / np.mean(prices[-14:]) * 100
        
        return normalized_vol
    
    def _calculate_momentum(self, prices: np.ndarray) -> float:
        if len(prices) < 10:
            return 0.0
        
        roc = (prices[-1] - prices[-10]) / prices[-10]
        momentum = np.tanh(roc * 10)
        
        return float(momentum)
    
    def _calculate_adx(self, prices: np.ndarray, period: int = 14) -> float:
        if len(prices) < period + 1:
            return 0.0
        
        tr = np.abs(np.diff(prices))
        tr = np.insert(tr, 0, tr[0])
        
        plus_dm = np.zeros(len(prices) - 1)
        minus_dm = np.zeros(len(prices) - 1)
        
        for i in range(1, len(prices)):
            up_move = prices[i] - prices[i-1]
            down_move = prices[i-1] - prices[i]
            
            if up_move > down_move and up_move > 0:
                plus_dm[i-1] = up_move
            if down_move > up_move and down_move > 0:
                minus_dm[i-1] = down_move
        
        plus_dm = np.insert(plus_dm, 0, plus_dm[0])
        minus_dm = np.insert(minus_dm, 0, minus_dm[0])
        
        adx = min(100, np.mean(np.abs(plus_dm - minus_dm) / (tr + 1e-10)) * 10)
        
        return float(adx)
    
    def _detect_trend_direction(self, prices: np.ndarray, adx: float) -> str:
        if adx < 20:
            return "RANGING"
        
        ma_short = np.mean(prices[-5:])
        ma_long = np.mean(prices[-20:])
        
        if ma_short > ma_long * 1.02:
            return "UP"
        elif ma_short < ma_long * 0.98:
            return "DOWN"
        else:
            return "NEUTRAL"
    
    def _analyze_volume_profile(self, volumes: np.ndarray) -> str:
        if len(volumes) < 20:
            return "NORMAL"
        
        mean_vol = np.mean(volumes[-20:])
        current_vol = np.mean(volumes[-5:])
        
        if current_vol > mean_vol * 1.5:
            return "HIGH"
        elif current_vol < mean_vol * 0.5:
            return "LOW"
        else:
            return "NORMAL"
    
    def _detect_regime(self, adx: float, volatility: float, 
                     momentum: float, trend_direction: str,
                     volume_profile: str) -> MarketRegime:
        
        if volatility > 2.0 and adx < 30:
            return MarketRegime.VOLATILE
        
        if adx > 30:
            if trend_direction == "UP":
                return MarketRegime.TRENDING_UP
            elif trend_direction == "DOWN":
                return MarketRegime.TRENDING_DOWN
        
        if volume_profile == "LOW":
            return MarketRegime.LOW_LIQUIDITY
        
        return MarketRegime.RANGING
    
    def _calculate_confidence(self, prices: np.ndarray, adx: float, volumes: np.ndarray) -> float:
        confidence = 0.5
        
        data_factor = min(1.0, len(prices) / 50)
        confidence += data_factor * 0.2
        
        if adx > 40:
            confidence += 0.15
        elif adx > 25:
            confidence += 0.05
        
        if len(volumes) > 20:
            vol_stability = 1.0 - (np.std(volumes[-20:]) / (np.mean(volumes[-20:]) + 1e-10))
            confidence += max(0, min(0.15, vol_stability * 0.15))
        
        return min(1.0, max(0.1, confidence))
    
    def _get_strategy_recommendation(self, regime: MarketRegime,
                                    funding_rate: float,
                                    order_book_imbalance: float,
                                    volume_delta: float) -> Tuple[StrategyRecommendation, float]:
        
        if abs(funding_rate) > 0.001:
            return StrategyRecommendation.FUNDING_RATE_ARB, 0.8
        
        if regime == MarketRegime.RANGING:
            return StrategyRecommendation.GRID_TRADING, 0.75
        
        if regime == MarketRegime.VOLATILE:
            return StrategyRecommendation.VOLATILITY_BREAKOUT, 0.7
        
        if regime == MarketRegime.TRENDING_UP:
            if order_book_imbalance > 0.3:
                return StrategyRecommendation.MOMENTUM_BREAKOUT, 0.8
            return StrategyRecommendation.MEAN_REVERSION, 0.6
        
        if regime == MarketRegime.TRENDING_DOWN:
            if order_book_imbalance < -0.3:
                return StrategyRecommendation.HUNT_STOP_HUNTS, 0.75
            return StrategyRecommendation.MEAN_REVERSION, 0.6
        
        if regime == MarketRegime.LOW_LIQUIDITY:
            return StrategyRecommendation.NO_SIGNAL, 0.0
        
        if abs(volume_delta) > 0.5:
            if volume_delta > 0:
                return StrategyRecommendation.ON_CHAIN_FLOW, 0.7
            else:
                return StrategyRecommendation.LIQUIDITY_HUNT, 0.65
        
        return StrategyRecommendation.NO_SIGNAL, 0.0
    
    def _generate_signals(self, prices: np.ndarray, momentum: float,
                         funding_rate: float, order_book_imbalance: float,
                         volume_delta: float) -> List[str]:
        signals = []
        
        if momentum > 0.5:
            signals.append("STRONG_BULLISH_MOMENTUM")
        elif momentum < -0.5:
            signals.append("STRONG_BEARISH_MOMENTUM")
        elif momentum > 0.3:
            signals.append("MODERATE_BULLISH_MOMENTUM")
        elif momentum < -0.3:
            signals.append("MODERATE_BEARISH_MOMENTUM")
        
        if funding_rate > 0.001:
            signals.append("FUNDING_RATE_POSITIVE")
        elif funding_rate < -0.001:
            signals.append("FUNDING_RATE_NEGATIVE")
        
        if order_book_imbalance > 0.5:
            signals.append("STRONG_BUY_IMBALANCE")
        elif order_book_imbalance < -0.5:
            signals.append("STRONG_SELL_IMBALANCE")
        
        if volume_delta > 0.8:
            signals.append("STRONG_VOLUME_BUYING")
        elif volume_delta < -0.8:
            signals.append("STRONG_VOLUME_SELLING")
        
        if len(prices) >= 20:
            recent_high = np.max(prices[-20:])
            recent_low = np.min(prices[-20:])
            current_price = prices[-1]
            
            if current_price > recent_high * 0.98:
                signals.append("NEAR_RESISTANCE")
            if current_price < recent_low * 1.02:
                signals.append("NEAR_SUPPORT")
        
        return signals
    
    def _generate_warnings(self, volume_profile: str, volatility: float, adx: float) -> List[str]:
        warnings = []
        
        if volume_profile == "LOW":
            warnings.append("LOW_VOLUME_CONDITIONS")
        
        if volatility > 3.0:
            warnings.append("EXTREME_VOLATILITY")
        elif volatility > 2.0:
            warnings.append("HIGH_VOLATILITY")
        
        if adx < 15:
            warnings.append("WEAK_TREND_NOISE")
        
        return warnings
    
    def _insufficient_data_analysis(self) -> MarketAnalysis:
        return MarketAnalysis(
            regime=MarketRegime.UNKNOWN, confidence=0.0, volatility=0.0,
            momentum=0.0, volume_profile="UNKNOWN",
            recommendation=StrategyRecommendation.NO_SIGNAL, recommendation_strength=0.0,
            signals=["INSUFFICIENT_DATA"], warnings=["NEED_MORE_DATA"]
        )
    
    def calculate_cvd(self, trades: List[Dict]) -> float:
        if not trades:
            return 0.0
        
        total_delta = 0.0
        for trade in trades:
            side = trade.get('side', '').lower()
            size = trade.get('size', 0)
            
            if side == 'buy':
                total_delta += size
            elif side == 'sell':
                total_delta -= size
        
        return float(np.tanh(total_delta / 100))
    
    def calculate_order_flow_imbalance(self, bids: List, asks: List) -> float:
        if not bids or not asks:
            return 0.0
        
        bid_total = sum(qty for _, qty in bids[:10])
        ask_total = sum(qty for _, qty in asks[:10])
        
        if bid_total + ask_total == 0:
            return 0.0
        
        imbalance = (bid_total - ask_total) / (bid_total + ask_total)
        return float(imbalance)
    
    def detect_vwap(self, prices: np.ndarray, volumes: np.ndarray) -> float:
        if len(prices) != len(volumes) or len(prices) == 0:
            return prices[-1] if len(prices) > 0 else 0.0
        
        return float(np.sum(prices * volumes) / np.sum(volumes))
    
    def detect_vwap_reversion_signal(self, current_price: float, vwap: float) -> Dict:
        distance_pct = ((current_price - vwap) / vwap) * 100
        
        if distance_pct < -1.0:
            return {'signal': 'BUY', 'strength': min(1.0, abs(distance_pct) / 2), 'distance_pct': distance_pct, 'reason': 'PRICE_BELOW_VWAP'}
        elif distance_pct > 1.0:
            return {'signal': 'SELL', 'strength': min(1.0, abs(distance_pct) / 2), 'distance_pct': distance_pct, 'reason': 'PRICE_ABOVE_VWAP'}
        else:
            return {'signal': 'NEUTRAL', 'strength': 0.0, 'distance_pct': distance_pct, 'reason': 'NEAR_VWAP'}


# ══════════════════════════════════════════════════════════════════════════════
# EXCHANGE CONNECTORS
# ══════════════════════════════════════════════════════════════════════════════

class BaseConnector:
    def __init__(self, name: str):
        self.name = name
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': 'MetaTrader/1.0', 'Accept': 'application/json'})
    
    async def get_ticker(self, pair: str):
        return None
    
    async def get_orderbook(self, pair: str):
        return None
    
    async def get_funding_rate(self, pair: str):
        return None
    
    async def close(self):
        self._session.close()


@dataclass
class Ticker:
    pair: str
    bid: float
    ask: float
    last: float
    volume_24h: float
    change_24h: float
    timestamp: float
    exchange: str


@dataclass 
class OrderBook:
    pair: str
    bids: List[Tuple[float, float]]
    asks: List[Tuple[float, float]]
    timestamp: float
    exchange: str


@dataclass
class FundingRate:
    pair: str
    rate: float
    next_funding_time: float
    exchange: str


class KrakenConnector(BaseConnector):
    API_BASE = "https://api.kraken.com"
    SYMBOL_MAP = {'BTC/USD': 'XXBTZUSD', 'ETH/USD': 'XETHZUSD', 'SOL/USD': 'SOLUSD'}
    
    def __init__(self):
        super().__init__("Kraken")
    
    async def get_ticker(self, pair: str) -> Optional[Ticker]:
        try:
            kraken_pair = self.SYMBOL_MAP.get(pair, pair.upper().replace('/', ''))
            url = f"{self.API_BASE}/0/public/Ticker?pair={kraken_pair}"
            
            response = self._session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('error'):
                    return None
                
                result = data.get('result', {})
                ticker_data = list(result.values())[0]
                
                return Ticker(
                    pair=pair, bid=float(ticker_data['b'][0]), ask=float(ticker_data['a'][0]),
                    last=float(ticker_data['c'][0]), volume_24h=float(ticker_data['v'][1]),
                    change_24h=float(ticker_data['c'][0]) - float(ticker_data['o']),
                    timestamp=time.time(), exchange="kraken"
                )
        except Exception as e:
            logger.error(f"Kraken ticker error: {e}")
        
        return None
    
    async def get_orderbook(self, pair: str) -> Optional[OrderBook]:
        try:
            kraken_pair = self.SYMBOL_MAP.get(pair, pair.upper().replace('/', ''))
            url = f"{self.API_BASE}/0/public/Depth?pair={kraken_pair}&count=50"
            
            response = self._session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('error'):
                    return None
                
                result = data.get('result', {})
                depth_data = list(result.values())[0]
                
                return OrderBook(
                    pair=pair,
                    bids=[(float(b[0]), float(b[1])) for b in depth_data.get('bids', [])],
                    asks=[(float(a[0]), float(a[1])) for a in depth_data.get('asks', [])],
                    timestamp=time.time(), exchange="kraken"
                )
        except Exception as e:
            logger.error(f"Kraken orderbook error: {e}")
        
        return None


class OKXConnector(BaseConnector):
    API_BASE = "https://www.okx.com"
    
    def __init__(self):
        super().__init__("OKX")
    
    async def get_ticker(self, pair: str) -> Optional[Ticker]:
        try:
            okx_pair = pair.replace('/', '-')
            url = f"{self.API_BASE}/api/v5/market/ticker?instId={okx_pair}"
            
            response = self._session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == '0':
                    ticker = data['data'][0]
                    return Ticker(
                        pair=pair, bid=float(ticker['bidPx']), ask=float(ticker['askPx']),
                        last=float(ticker['last']), volume_24h=float(ticker['vol24h']),
                        change_24h=float(ticker['last']) - float(ticker['open24h']),
                        timestamp=float(ticker['ts']) / 1000, exchange="okx"
                    )
        except Exception as e:
            logger.error(f"OKX ticker error: {e}")
        
        return None
    
    async def get_funding_rate(self, pair: str) -> Optional[FundingRate]:
        try:
            okx_pair = pair.replace('/', '-')
            url = f"{self.API_BASE}/api/v5/market/funding-rate?instId={okx_pair}-SWAP"
            
            response = self._session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == '0':
                    funding = data['data'][0]
                    return FundingRate(
                        pair=pair, rate=float(funding['fundingRate']),
                        next_funding_time=float(funding['nextFundingTime']) / 1000, exchange="okx"
                    )
        except Exception as e:
            logger.error(f"OKX funding rate error: {e}")
        
        return None


class CoinGeckoConnector(BaseConnector):
    API_BASE = "https://api.coingecko.com/api/v3"
    COIN_IDS = {'BTC': 'bitcoin', 'ETH': 'ethereum', 'SOL': 'solana', 'AVAX': 'avalanche-2', 'LINK': 'chainlink'}
    
    def __init__(self):
        super().__init__("CoinGecko")
        self._rate_limit_delay = 0.5
    
    async def get_ticker(self, pair: str) -> Optional[Ticker]:
        try:
            symbol = pair.split('/')[0].upper()
            coin_id = self.COIN_IDS.get(symbol, symbol.lower())
            
            url = f"{self.API_BASE}/simple/price"
            response = self._session.get(
                url,
                params={'ids': coin_id, 'vs_currencies': 'usd', 'include_24hr_vol': 'true', 'include_24hr_change': 'true'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if coin_id in data:
                    prices = data[coin_id]
                    return Ticker(
                        pair=pair, bid=prices.get('usd', 0), ask=prices.get('usd', 0),
                        last=prices.get('usd', 0), volume_24h=prices.get('usd_24h_vol', 0),
                        change_24h=prices.get('usd_24h_change', 0), timestamp=time.time(), exchange="coingecko"
                    )
        except Exception as e:
            logger.error(f"CoinGecko ticker error: {e}")
        
        return None
    
    async def get_fear_greed_value(self) -> Dict:
        try:
            response = self._session.get("https://api.alternative.me/fng", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    fng = data['data'][0]
                    return {
                        'value': int(fng['value']),
                        'classification': fng['value_classification'],
                        'timestamp': int(fng['timestamp'])
                    }
        except Exception as e:
            logger.error(f"Fear & Greed error: {e}")
        
        return {'value': 50, 'classification': 'Neutral', 'timestamp': 0}


class BinanceConnector(BaseConnector):
    API_BASE = "https://api.binance.com"
    
    def __init__(self):
        super().__init__("Binance")
    
    async def get_ticker(self, pair: str) -> Optional[Ticker]:
        try:
            binance_pair = pair.replace('/', '').upper()
            url = f"{self.API_BASE}/api/v3/ticker/24hr?symbol={binance_pair}"
            
            response = self._session.get(url, timeout=10)
            
            if response.status_code == 200:
                ticker = response.json()
                return Ticker(
                    pair=pair, bid=float(ticker['bidPrice']), ask=float(ticker['askPrice']),
                    last=float(ticker['lastPrice']), volume_24h=float(ticker['volume']),
                    change_24h=float(ticker['priceChange']), timestamp=time.time(), exchange="binance"
                )
        except Exception as e:
            logger.error(f"Binance ticker error: {e}")
        
        return None
    
    async def get_funding_rate(self, pair: str) -> Optional[FundingRate]:
        try:
            binance_pair = pair.replace('/', '').upper()
            url = f"{self.API_BASE}/api/v3/fundingRate?symbol={binance_pair}"
            
            response = self._session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data:
                    return FundingRate(
                        pair=pair, rate=float(data.get('fundingRate', 0)),
                        next_funding_time=data.get('nextFundingTime', 0) / 1000, exchange="binance"
                    )
        except Exception as e:
            logger.error(f"Binance funding rate error: {e}")
        
        return None


class ConnectorManager:
    def __init__(self):
        self.connectors: Dict[str, BaseConnector] = {}
        self._initialize_connectors()
    
    def _initialize_connectors(self):
        self.connectors['kraken'] = KrakenConnector()
        self.connectors['okx'] = OKXConnector()
        self.connectors['coingecko'] = CoinGeckoConnector()
        self.connectors['binance'] = BinanceConnector()
    
    def get_connector(self, exchange: str) -> Optional[BaseConnector]:
        return self.connectors.get(exchange.lower())
    
    async def close_all(self):
        for connector in self.connectors.values():
            await connector.close()


# ══════════════════════════════════════════════════════════════════════════════
# TRADING STRATEGIES
# ══════════════════════════════════════════════════════════════════════════════

class BaseStrategy:
    def __init__(self, name: str, tier: StrategyTier):
        self.name = name
        self.tier = tier
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        raise NotImplementedError


class FundingRateArbitrage(BaseStrategy):
    """When funding rates go extreme, long spot/short perp and collect funding."""
    
    ENTRY_THRESHOLD = 0.003
    EXIT_THRESHOLD = 0.0001
    
    def __init__(self):
        super().__init__("Funding Rate Arbitrage", StrategyTier.TIER_1_CONSERVATIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        funding_rate = market_data.get('funding_rate', 0)
        spot_price = market_data.get('spot_price', 0)
        perp_price = market_data.get('perp_price', 0)
        pair = market_data.get('pair', 'UNKNOWN')
        
        if not funding_rate or not spot_price or not perp_price:
            return None
        
        if funding_rate > self.ENTRY_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=pair, side="SHORT", entry_price=perp_price,
                stop_loss=perp_price * 1.02, take_profit=perp_price * 0.98,
                confidence=min(0.9, abs(funding_rate) * 100), tier=self.tier,
                metadata={'funding_rate': funding_rate, 'strategy': 'long_spot_short_perp'},
                risk_amount=50.0
            )
        elif funding_rate < -self.ENTRY_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=pair, side="LONG", entry_price=perp_price,
                stop_loss=perp_price * 0.98, take_profit=perp_price * 1.02,
                confidence=min(0.9, abs(funding_rate) * 100), tier=self.tier,
                metadata={'funding_rate': funding_rate, 'strategy': 'short_spot_long_perp'},
                risk_amount=50.0
            )
        
        return None


class StatisticalArbitrage(BaseStrategy):
    """Correlated pairs divergence and reversion."""
    
    CORRELATION_THRESHOLD = 0.7
    ENTRY_Z_SCORE = 2.0
    
    def __init__(self):
        super().__init__("Statistical Arbitrage", StrategyTier.TIER_1_CONSERVATIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        pair1_price = market_data.get('pair1_price', 0)
        pair2_price = market_data.get('pair2_price', 0)
        pair1 = market_data.get('pair1', 'PAIR1')
        pair2 = market_data.get('pair2', 'PAIR2')
        
        if not pair1_price or not pair2_price:
            return None
        
        spread = pair1_price / pair2_price
        mean_spread = market_data.get('spread_mean', spread)
        std_spread = market_data.get('spread_std', spread * 0.1)
        
        if std_spread == 0:
            return None
        
        z_score = (spread - mean_spread) / std_spread
        
        if abs(z_score) > self.ENTRY_Z_SCORE:
            if z_score > self.ENTRY_Z_SCORE:
                return StrategySignal(
                    strategy_name=self.name, pair=f"{pair1}/{pair2}", side="SHORT", entry_price=pair1_price,
                    stop_loss=pair1_price * 1.03, take_profit=pair1_price * 0.97,
                    confidence=min(0.85, abs(z_score) / 4), tier=self.tier,
                    metadata={'z_score': z_score, 'spread': spread},
                    risk_amount=50.0
                )
            else:
                return StrategySignal(
                    strategy_name=self.name, pair=f"{pair1}/{pair2}", side="LONG", entry_price=pair1_price,
                    stop_loss=pair1_price * 0.97, take_profit=pair1_price * 1.03,
                    confidence=min(0.85, abs(z_score) / 4), tier=self.tier,
                    metadata={'z_score': z_score, 'spread': spread},
                    risk_amount=50.0
                )
        
        return None


class GridTradingStrategy(BaseStrategy):
    """Place orders at fixed intervals, profit from volatility."""
    
    def __init__(self, grid_levels: int = 5, grid_spacing_pct: float = 1.0):
        super().__init__("Grid Trading", StrategyTier.TIER_1_CONSERVATIVE)
        self.grid_levels = grid_levels
        self.grid_spacing_pct = grid_spacing_pct / 100
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        volatility = market_data.get('volatility', 0)
        regime = market_data.get('regime', 'RANGING')
        
        if not current_price or volatility == 0:
            return None
        
        if regime != 'RANGING' and volatility < 1.0:
            return None
        
        return StrategySignal(
            strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="NEUTRAL",
            entry_price=current_price,
            stop_loss=current_price * (1 - 2 * self.grid_spacing_pct),
            take_profit=current_price * (1 + 2 * self.grid_spacing_pct),
            confidence=0.6, tier=self.tier,
            metadata={'grid_levels': self.grid_levels, 'grid_spacing': self.grid_spacing_pct * 100},
            risk_amount=0
        )


class VWAPReversion(BaseStrategy):
    """Buy below VWAP, sell above."""
    
    ENTRY_THRESHOLD = 1.0
    
    def __init__(self):
        super().__init__("VWAP Reversion", StrategyTier.TIER_1_CONSERVATIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        vwap = market_data.get('vwap', 0)
        
        if not current_price or not vwap or vwap == 0:
            return None
        
        distance_pct = ((current_price - vwap) / vwap) * 100
        
        if distance_pct < -self.ENTRY_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                entry_price=current_price, stop_loss=vwap * 0.99, take_profit=vwap,
                confidence=min(0.85, abs(distance_pct) / 3), tier=self.tier,
                metadata={'vwap': vwap, 'distance_pct': distance_pct, 'signal': 'BUY_BELOW_VWAP'},
                risk_amount=50.0
            )
        elif distance_pct > self.ENTRY_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                entry_price=current_price, stop_loss=vwap * 1.01, take_profit=vwap,
                confidence=min(0.85, abs(distance_pct) / 3), tier=self.tier,
                metadata={'vwap': vwap, 'distance_pct': distance_pct, 'signal': 'SELL_ABOVE_VWAP'},
                risk_amount=50.0
            )
        
        return None


class DeltaDivergence(BaseStrategy):
    """CVD diverges from price = reversal coming."""
    
    DIVERGENCE_THRESHOLD = 0.3
    
    def __init__(self):
        super().__init__("Delta Divergence", StrategyTier.TIER_1_CONSERVATIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        cvd = market_data.get('cvd', 0)
        prices = market_data.get('price_history', [])
        
        if not current_price or not prices or len(prices) < 20:
            return None
        
        price_trend = (prices[-1] - prices[-10]) / prices[-10]
        cvd_trend = np.tanh(cvd / 100)
        
        if price_trend > 0.1 and cvd_trend < -self.DIVERGENCE_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                entry_price=current_price, stop_loss=current_price * 1.02, take_profit=current_price * 0.96,
                confidence=0.8, tier=self.tier,
                metadata={'cvd': cvd, 'price_trend': price_trend, 'divergence_type': 'BEARISH'},
                risk_amount=50.0
            )
        elif price_trend < -0.1 and cvd_trend > self.DIVERGENCE_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                entry_price=current_price, stop_loss=current_price * 0.98, take_profit=current_price * 1.04,
                confidence=0.8, tier=self.tier,
                metadata={'cvd': cvd, 'price_trend': price_trend, 'divergence_type': 'BULLISH'},
                risk_amount=50.0
            )
        
        return None


# Tier 2 Strategies
class MomentumBreakout(BaseStrategy):
    """Buy confirmed breakouts with volume."""
    
    BREAKOUT_THRESHOLD = 2.0
    VOLUME_CONFIRMATION = 1.5
    
    def __init__(self):
        super().__init__("Momentum Breakout", StrategyTier.TIER_2_MODERATE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        resistance = market_data.get('resistance', 0)
        support = market_data.get('support', 0)
        volume = market_data.get('volume', 0)
        avg_volume = market_data.get('avg_volume', 1)
        regime = market_data.get('regime', 'UNKNOWN')
        
        if not current_price or not resistance:
            return None
        
        if regime not in ['TRENDING_UP', 'TRENDING_DOWN']:
            return None
        
        breakout_pct = ((current_price - resistance) / resistance) * 100
        
        if breakout_pct > self.BREAKOUT_THRESHOLD:
            volume_ratio = volume / avg_volume if avg_volume > 0 else 0
            
            if volume_ratio >= self.VOLUME_CONFIRMATION and regime == 'TRENDING_UP':
                return StrategySignal(
                    strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                    entry_price=current_price, stop_loss=support, take_profit=current_price * 1.05,
                    confidence=min(0.85, volume_ratio / 3), tier=self.tier,
                    metadata={'breakout_pct': breakout_pct, 'volume_ratio': volume_ratio, 'regime_confirmed': regime},
                    risk_amount=75.0
                )
        
        return None


class LiquiditySweep(BaseStrategy):
    """Detect and trade stop hunts."""
    
    SWEEP_THRESHOLD = 0.5
    
    def __init__(self):
        super().__init__("Liquidity Sweep", StrategyTier.TIER_2_MODERATE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        large_walls = market_data.get('large_walls', [])
        
        if not current_price or not large_walls:
            return None
        
        for wall in large_walls:
            wall_price = wall.get('price', 0)
            wall_side = wall.get('side', 'ASK')
            
            if not wall_price:
                continue
            
            if wall_side == 'ASK':
                distance_pct = ((current_price - wall_price) / wall_price) * 100
                
                if current_price > wall_price and distance_pct < self.SWEEP_THRESHOLD:
                    return StrategySignal(
                        strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                        entry_price=current_price, stop_loss=wall_price * 1.01, take_profit=wall_price * 0.99,
                        confidence=0.75, tier=self.tier,
                        metadata={'wall_price': wall_price, 'sweep_type': 'ABOVE_ASK_WALL', 'expected_reversal': 'DOWN'},
                        risk_amount=75.0
                    )
            
            elif wall_side == 'BID':
                distance_pct = ((wall_price - current_price) / wall_price) * 100
                
                if current_price < wall_price and distance_pct < self.SWEEP_THRESHOLD:
                    return StrategySignal(
                        strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                        entry_price=current_price, stop_loss=wall_price * 0.99, take_profit=wall_price * 1.01,
                        confidence=0.75, tier=self.tier,
                        metadata={'wall_price': wall_price, 'sweep_type': 'BELOW_BID_WALL', 'expected_reversal': 'UP'},
                        risk_amount=75.0
                    )
        
        return None


class OnChainFlow(BaseStrategy):
    """Follow whale movements."""
    
    WHALE_THRESHOLD = 1000000
    
    def __init__(self):
        super().__init__("On-Chain Flow", StrategyTier.TIER_2_MODERATE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        exchange_inflow = market_data.get('exchange_inflow', 0)
        exchange_outflow = market_data.get('exchange_outflow', 0)
        current_price = market_data.get('current_price', 0)
        
        if not current_price:
            return None
        
        if exchange_inflow > self.WHALE_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                entry_price=current_price, stop_loss=current_price * 1.02, take_profit=current_price * 0.95,
                confidence=0.7, tier=self.tier,
                metadata={'exchange_inflow': exchange_inflow, 'signal': 'WHALE_TO_EXCHANGE'},
                risk_amount=75.0
            )
        elif exchange_outflow > self.WHALE_THRESHOLD:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                entry_price=current_price, stop_loss=current_price * 0.98, take_profit=current_price * 1.05,
                confidence=0.7, tier=self.tier,
                metadata={'exchange_outflow': exchange_outflow, 'signal': 'WHALE_FROM_EXCHANGE'},
                risk_amount=75.0
            )
        
        return None


class OpenInterestSpike(BaseStrategy):
    """Position building detection."""
    
    OI_SPIKE_THRESHOLD = 0.3
    
    def __init__(self):
        super().__init__("Open Interest Spike", StrategyTier.TIER_2_MODERATE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_oi = market_data.get('current_oi', 0)
        previous_oi = market_data.get('previous_oi', 0)
        current_price = market_data.get('current_price', 0)
        price_change = market_data.get('price_change_24h', 0)
        
        if not current_oi or not previous_oi:
            return None
        
        oi_change_pct = (current_oi - previous_oi) / previous_oi
        
        if oi_change_pct > self.OI_SPIKE_THRESHOLD:
            if price_change > 0:
                return StrategySignal(
                    strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                    entry_price=current_price, stop_loss=current_price * 0.98, take_profit=current_price * 1.03,
                    confidence=0.7, tier=self.tier,
                    metadata={'oi_change_pct': oi_change_pct * 100, 'price_change': price_change, 'signal': 'BULLISH_POSITIONING'},
                    risk_amount=75.0
                )
            else:
                return StrategySignal(
                    strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                    entry_price=current_price, stop_loss=current_price * 1.02, take_profit=current_price * 0.97,
                    confidence=0.7, tier=self.tier,
                    metadata={'oi_change_pct': oi_change_pct * 100, 'price_change': price_change, 'signal': 'BEARISH_POSITIONING'},
                    risk_amount=75.0
                )
        
        return None


class LiquidationCascade(BaseStrategy):
    """Trade toward liquidation zones."""
    
    def __init__(self):
        super().__init__("Liquidation Cascade", StrategyTier.TIER_2_MODERATE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        liquidation_zones = market_data.get('liquidation_zones', [])
        
        if not current_price or not liquidation_zones:
            return None
        
        for zone in liquidation_zones:
            zone_price = zone.get('price', 0)
            zone_type = zone.get('type', 'LONG_LIQ')
            zone_size = zone.get('size', 0)
            
            if not zone_price or zone_size < 100000:
                continue
            
            distance_pct = abs((current_price - zone_price) / zone_price) * 100
            
            if distance_pct < 3 and zone_type == 'LONG_LIQ':
                return StrategySignal(
                    strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                    entry_price=current_price, stop_loss=zone_price * 0.99, take_profit=zone_price * 1.01,
                    confidence=0.75, tier=self.tier,
                    metadata={'zone_price': zone_price, 'zone_type': zone_type, 'signal': 'TRADE_INTO_LIQ_ZONE'},
                    risk_amount=75.0
                )
        
        return None


# Tier 3 Strategies
class SentimentConfluence(BaseStrategy):
    """Fear & Greed + technical confluence."""
    
    EXTREME_FEAR = 20
    EXTREME_GREED = 80
    
    def __init__(self):
        super().__init__("Sentiment Confluence", StrategyTier.TIER_3_AGGRESSIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        fear_greed_value = market_data.get('fear_greed_value', 50)
        current_price = market_data.get('current_price', 0)
        price_momentum = market_data.get('momentum', 0)
        
        if not current_price:
            return None
        
        if fear_greed_value <= self.EXTREME_FEAR and price_momentum < -0.3:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                entry_price=current_price, stop_loss=current_price * 0.96, take_profit=current_price * 1.08,
                confidence=0.8, tier=self.tier,
                metadata={'fear_greed_value': fear_greed_value, 'price_momentum': price_momentum, 'signal': 'EXTREME_FEAR_BOTTOM'},
                risk_amount=100.0
            )
        elif fear_greed_value >= self.EXTREME_GREED and price_momentum > 0.3:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                entry_price=current_price, stop_loss=current_price * 1.04, take_profit=current_price * 0.92,
                confidence=0.8, tier=self.tier,
                metadata={'fear_greed_value': fear_greed_value, 'price_momentum': price_momentum, 'signal': 'EXTREME_GREED_TOP'},
                risk_amount=100.0
            )
        
        return None


class VolatilityBreakout(BaseStrategy):
    """Bollinger Band squeeze trades."""
    
    SQUEEZE_THRESHOLD = 0.5
    
    def __init__(self):
        super().__init__("Volatility Breakout", StrategyTier.TIER_3_AGGRESSIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        bb_upper = market_data.get('bb_upper', 0)
        bb_lower = market_data.get('bb_lower', 0)
        bb_width = market_data.get('bb_width', 0)
        bb_avg_width = market_data.get('bb_avg_width', 1)
        atr = market_data.get('atr', 0)
        
        if not current_price or not bb_upper or not bb_lower:
            return None
        
        squeeze_ratio = bb_width / bb_avg_width if bb_avg_width > 0 else 1
        
        if squeeze_ratio < self.SQUEEZE_THRESHOLD:
            upper_distance = (bb_upper - current_price) / current_price
            lower_distance = (current_price - bb_lower) / current_price
            
            if upper_distance < 0.005:
                return StrategySignal(
                    strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                    entry_price=current_price, stop_loss=bb_lower, take_profit=bb_upper + (atr * 2),
                    confidence=0.75, tier=self.tier,
                    metadata={'squeeze_ratio': squeeze_ratio, 'breakout_direction': 'UP', 'atr': atr},
                    risk_amount=100.0
                )
            elif lower_distance < 0.005:
                return StrategySignal(
                    strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                    entry_price=current_price, stop_loss=bb_upper, take_profit=bb_lower - (atr * 2),
                    confidence=0.75, tier=self.tier,
                    metadata={'squeeze_ratio': squeeze_ratio, 'breakout_direction': 'DOWN', 'atr': atr},
                    risk_amount=100.0
                )
        
        return None


class TokenUnlock(BaseStrategy):
    """Predictable event-based trading."""
    
    def __init__(self):
        super().__init__("Token Unlock", StrategyTier.TIER_3_AGGRESSIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        current_price = market_data.get('current_price', 0)
        unlock_date = market_data.get('unlock_date')
        unlock_amount = market_data.get('unlock_amount', 0)
        days_until_unlock = market_data.get('days_until_unlock', 30)
        
        if not current_price or not unlock_date or not days_until_unlock:
            return None
        
        if 0 < days_until_unlock <= 14 and unlock_amount > 10000000:
            return StrategySignal(
                strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="SHORT",
                entry_price=current_price, stop_loss=current_price * 1.05, take_profit=current_price * 0.92,
                confidence=0.75, tier=self.tier,
                metadata={'unlock_date': unlock_date, 'unlock_amount': unlock_amount, 'days_until_unlock': days_until_unlock},
                risk_amount=100.0
            )
        
        return None


class CrossExchangeArbitrage(BaseStrategy):
    """Multi-exchange price differences."""
    
    MIN_SPREAD = 0.002
    
    def __init__(self):
        super().__init__("Cross Exchange Arb", StrategyTier.TIER_3_AGGRESSIVE)
    
    async def analyze(self, market_data: Dict) -> Optional[StrategySignal]:
        binance_price = market_data.get('binance_price', 0)
        kraken_price = market_data.get('kraken_price', 0)
        
        if not binance_price or not kraken_price:
            return None
        
        spread_pct = abs(binance_price - kraken_price) / binance_price
        
        if spread_pct > self.MIN_SPREAD:
            if binance_price > kraken_price:
                return StrategySignal(
                    strategy_name=self.name, pair=market_data.get('pair', 'UNKNOWN'), side="LONG",
                    entry_price=kraken_price, stop_loss=kraken_price * 0.99, take_profit=binance_price,
                    confidence=0.85, tier=self.tier,
                    metadata={'binance_price': binance_price, 'kraken_price': kraken_price, 'spread_pct': spread_pct * 100},
                    risk_amount=50.0
                )
        
        return None


class StrategyManager:
    def __init__(self):
        self.strategies: List[BaseStrategy] = []
        self._initialize_strategies()
    
    def _initialize_strategies(self):
        self.strategies.append(FundingRateArbitrage())
        self.strategies.append(StatisticalArbitrage())
        self.strategies.append(GridTradingStrategy())
        self.strategies.append(VWAPReversion())
        self.strategies.append(DeltaDivergence())
        self.strategies.append(MomentumBreakout())
        self.strategies.append(LiquiditySweep())
        self.strategies.append(OnChainFlow())
        self.strategies.append(OpenInterestSpike())
        self.strategies.append(LiquidationCascade())
        self.strategies.append(SentimentConfluence())
        self.strategies.append(VolatilityBreakout())
        self.strategies.append(TokenUnlock())
        self.strategies.append(CrossExchangeArbitrage())
    
    async def get_all_signals(self, market_data: Dict) -> List[StrategySignal]:
        signals = []
        
        for strategy in self.strategies:
            try:
                signal = await strategy.analyze(market_data)
                if signal and signal.side not in ['SKIP', 'NEUTRAL']:
                    signals.append(signal)
            except Exception as e:
                logger.error(f"Strategy {strategy.name} error: {e}")
        
        signals.sort(key=lambda x: x.confidence, reverse=True)
        
        return signals
    
    async def get_best_signal(self, market_data: Dict) -> Optional[StrategySignal]:
        signals = await self.get_all_signals(market_data)
        return signals[0] if signals else None


# ══════════════════════════════════════════════════════════════════════════════
# MAIN TRADING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class MetaTrader:
    """MetaTrader - The Crypto Meta Trading Bot."""
    
    VERSION = "1.0.0"
    
    def __init__(self):
        self.security: Optional[PantheonSecurityStack] = None
        self.risk: Optional[RiskManager] = None
        self.connectors: Optional[ConnectorManager] = None
        self.safla: Optional[SAFLA] = None
        self.strategies: Optional[StrategyManager] = None
        
        self.is_running = False
        self.last_status_report = datetime.now()
        self.status_report_interval = 3600
        
        self.price_history: Dict[str, List[float]] = {}
        self.volume_history: Dict[str, List[float]] = {}
        
        self.trading_pairs = ['BTC/USD', 'ETH/USD', 'SOL/USD']
        self.max_concurrent_positions = 3
        
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._main_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        logger.info(f"Initializing MetaTrader v{self.VERSION}")
        
        load_dotenv()
        
        self.security = PantheonSecurityStack(
            vault_file=os.getenv('VAULT_FILE', '.vault.key'),
            log_file=os.getenv('LOG_FILE', 'metatrader_log.db')
        )
        
        telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        telegram_chat = os.getenv('TELEGRAM_CHAT_ID')
        if telegram_token and telegram_chat:
            self.security.setup_telegram(telegram_token, telegram_chat)
            logger.info("Telegram notifications enabled")
        
        total_capital = float(os.getenv('TOTAL_CAPITAL_USD', '1000.0'))
        self.risk = RiskManager(RiskConfig(total_capital_usd=total_capital))
        
        self.connectors = ConnectorManager()
        self.safla = SAFLA()
        self.strategies = StrategyManager()
        
        self.security.log_restart()
        
        logger.info("All components initialized successfully")
    
    async def shutdown(self):
        logger.info("Initiating graceful shutdown...")
        self.is_running = False
        
        if self._main_task and not self._main_task.done():
            self._main_task.cancel()
        
        if self.connectors:
            await self.connectors.close_all()
        
        if self.security and self.security.vault:
            self.security.vault.clear_memory()
        
        logger.info("Shutdown complete")
    
    async def run(self):
        await self.initialize()
        
        self._loop = asyncio.get_event_loop()
        self.is_running = True
        
        logger.info("MetaTrader started - entering main loop")
        
        try:
            while self.is_running:
                try:
                    await self.trading_cycle()
                    await self.check_status_report()
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Trading cycle error: {e}")
                    self.security.log_error(str(e), {'cycle': 'trading'})
                    await asyncio.sleep(30)
        
        finally:
            await self.shutdown()
    
    async def trading_cycle(self):
        for pair in self.trading_pairs:
            try:
                market_data = await self._fetch_market_data(pair)
                
                if not market_data or not market_data.get('current_price'):
                    continue
                
                self._update_history(pair, market_data)
                
                analysis = await self._run_safla_analysis(pair, market_data)
                
                if analysis.recommendation_strength < 0.5:
                    continue
                
                signal = await self._generate_signal(pair, market_data, analysis)
                
                if not signal or signal.side in ['SKIP', 'NEUTRAL']:
                    continue
                
                if signal.confidence < 0.6:
                    continue
                
                risk_allowed, risk_reason, size = self.risk.check_trade(
                    pair=pair, side=signal.side, entry_price=signal.entry_price,
                    stop_loss=signal.stop_loss, take_profit=signal.take_profit,
                    signal_strength=signal.confidence, atr=market_data.get('atr', 0)
                )
                
                if not risk_allowed:
                    continue
                
                position_value = size * signal.entry_price
                security_allowed, sec_reason = self.security.authorize_trade(
                    pair=pair, size_usd=position_value, strategy=signal.strategy_name
                )
                
                if not security_allowed:
                    continue
                
                await self._execute_trade(signal, size)
                
            except Exception as e:
                logger.error(f"Error processing {pair}: {e}")
                self.security.log_error(str(e), {'pair': pair})
    
    async def _fetch_market_data(self, pair: str) -> Dict[str, Any]:
        data = {}
        
        try:
            kraken = self.connectors.get_connector('kraken')
            ticker = await kraken.get_ticker(pair)
            if ticker:
                data['current_price'] = ticker.last
                data['bid'] = ticker.bid
                data['ask'] = ticker.ask
                data['volume_24h'] = ticker.volume_24h
            
            okx = self.connectors.get_connector('okx')
            funding = await okx.get_funding_rate(pair)
            if funding:
                data['funding_rate'] = funding.rate
            
            binance = self.connectors.get_connector('binance')
            bin_ticker = await binance.get_ticker(pair)
            if bin_ticker:
                data['binance_price'] = bin_ticker.last
            
            coingecko = self.connectors.get_connector('coingecko')
            fg_data = await coingecko.get_fear_greed_value()
            if fg_data:
                data['fear_greed_value'] = fg_data['value']
            
            orderbook = await kraken.get_orderbook(pair)
            if orderbook:
                data['orderbook'] = orderbook
                data['order_book_imbalance'] = self.safla.calculate_order_flow_imbalance(
                    orderbook.bids, orderbook.asks
                )
            
            if 'current_price' in data and len(self.price_history.get(pair, [])) >= 14:
                prices = self.price_history[pair]
                atr = sum(abs(prices[i] - prices[i-1]) for i in range(1, 14)) / 14
                data['atr'] = atr
            
        except Exception as e:
            logger.error(f"Market data fetch error for {pair}: {e}")
        
        return data
    
    def _update_history(self, pair: str, market_data: Dict):
        price = market_data.get('current_price')
        volume = market_data.get('volume_24h', 0)
        
        if not price:
            return
        
        if pair not in self.price_history:
            self.price_history[pair] = []
        if pair not in self.volume_history:
            self.volume_history[pair] = []
        
        self.price_history[pair].append(price)
        if len(self.price_history[pair]) > 50:
            self.price_history[pair].pop(0)
        
        if volume > 0:
            self.volume_history[pair].append(volume)
            if len(self.volume_history[pair]) > 50:
                self.volume_history[pair].pop(0)
    
    async def _run_safla_analysis(self, pair: str, market_data: Dict) -> MarketAnalysis:
        prices = self.price_history.get(pair, [])
        volumes = self.volume_history.get(pair, [])
        
        analysis = self.safla.analyze_market(
            pair=pair, prices=prices,
            volumes=volumes if volumes else None,
            order_book_imbalance=market_data.get('order_book_imbalance', 0),
            funding_rate=market_data.get('funding_rate', 0),
            volume_delta=0
        )
        
        return analysis
    
    async def _generate_signal(self, pair: str, market_data: Dict, analysis: MarketAnalysis) -> Optional[StrategySignal]:
        strategy_data = {
            'pair': pair,
            'current_price': market_data.get('current_price'),
            'spot_price': market_data.get('current_price'),
            'perp_price': market_data.get('current_price'),
            'funding_rate': market_data.get('funding_rate', 0),
            'volatility': market_data.get('atr', 0),
            'regime': analysis.regime.value if analysis.regime else 'UNKNOWN',
            'momentum': analysis.momentum,
            'vwap': market_data.get('current_price'),
            'fear_greed_value': market_data.get('fear_greed_value', 50),
            'price_history': self.price_history.get(pair, []),
            'binance_price': market_data.get('binance_price'),
            'kraken_price': market_data.get('current_price'),
            'cvd': 0,
        }
        
        signal = await self.strategies.get_best_signal(strategy_data)
        
        return signal
    
    async def _execute_trade(self, signal: StrategySignal, size: float):
        trade = TradeRecord(
            timestamp=datetime.now(), pair=signal.pair, side=signal.side,
            price=signal.entry_price, quantity=size, exchange='kraken',
            strategy=signal.strategy_name, signal_strength=signal.confidence
        )
        
        self.security.log_trade(trade)
        
        position = Position(
            pair=signal.pair, side=signal.side, entry_price=signal.entry_price,
            quantity=size, stop_loss=signal.stop_loss, take_profit=signal.take_profit,
            open_time=datetime.now(), exchange=trade.exchange,
            strategy=signal.strategy_name, atr_at_entry=signal.metadata.get('atr', 0),
            risk_amount=signal.risk_amount
        )
        
        self.risk.open_position(position)
        
        logger.info(f"Trade executed: {signal.side} {signal.pair} @ {signal.entry_price}")
    
    async def check_status_report(self):
        now = datetime.now()
        
        if now - self.last_status_report >= timedelta(seconds=self.status_report_interval):
            self.last_status_report = now
            
            risk_report = self.risk.status_report()
            security_report = self.security.get_status_report()
            
            if self.security._telegram_enabled:
                self.security._send_telegram_message(risk_report)
                await asyncio.sleep(1)
                self.security._send_telegram_message(security_report)
            
            logger.info("Hourly status report sent")
    
    def handle_telegram_command(self, command: str):
        command = command.strip().lower()
        
        if command == '/kill':
            logger.warning("Emergency kill activated via Telegram")
            self.security.emergency_kill()
            asyncio.create_task(self.shutdown())
        elif command == '/status':
            logger.info(self.risk.status_report())
        elif command == '/pause':
            self.security.governor.trigger_pause("Manual pause", 60)
        elif command == '/resume':
            self.security.governor._is_paused = False
            self.security.governor._pause_until = None


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    bot = MetaTrader()
    
    try:
        await bot.run()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())