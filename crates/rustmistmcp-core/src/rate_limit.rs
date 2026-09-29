//! Per-token hourly Mist API call budget, with a reserve for human operators.
//!
//! Mist enforces 5,000 API calls/hour per token. A token is often shared by
//! an autonomous agent loop and a human operator using the same MCP server;
//! without a reserve, a runaway agent can consume the entire hourly budget
//! and lock the human out for the rest of the window. This tracker carves
//! off a fixed reserve that only [`CallPriority::Reserved`] callers may draw
//! from, so a human always has headroom even when the standard pool is spent.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The hourly window Mist's rate limit resets on.
const WINDOW: Duration = Duration::from_secs(3600);

/// Which pool a call draws its budget unit from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallPriority {
    /// Draws only from the non-reserved portion of the hourly budget.
    ///
    /// Used for autonomous/agent-initiated calls.
    Standard,
    /// May also draw from the reserve carved out for human operators.
    ///
    /// Used only for calls a server has verified are human-initiated (see
    /// `mecmcp_auth::ActorType::Human`); an unverified or agent actor must
    /// never be granted this priority.
    Reserved,
}

/// Point-in-time hourly headroom, safe to surface directly in tool output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetStatus {
    /// The configured hourly call ceiling for this token.
    pub hourly_limit: u32,
    /// The portion of `hourly_limit` reserved for [`CallPriority::Reserved`] callers.
    pub human_reserve: u32,
    /// Calls already counted against this hourly window.
    pub used: u32,
    /// Calls a [`CallPriority::Standard`] caller may still make this window.
    pub remaining_standard: u32,
    /// Calls a [`CallPriority::Reserved`] caller may still make this window.
    pub remaining_reserved: u32,
}

/// The hourly budget (including any reserve available to this priority) is spent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Mist hourly call budget exhausted for this token")]
pub struct BudgetExhausted;

struct Window {
    started_at: Instant,
    used: u32,
}

/// Tracks one Mist API token's hourly call budget across every caller sharing it.
pub struct RateLimitBudget {
    hourly_limit: u32,
    human_reserve: u32,
    window: Mutex<Window>,
}

impl RateLimitBudget {
    /// Build a tracker for one token.
    ///
    /// `human_reserve` is clamped to `hourly_limit` so a misconfigured reserve
    /// cannot make the standard pool negative.
    #[must_use]
    pub fn new(hourly_limit: u32, human_reserve: u32) -> Self {
        Self {
            hourly_limit,
            human_reserve: human_reserve.min(hourly_limit),
            window: Mutex::new(Window {
                started_at: Instant::now(),
                used: 0,
            }),
        }
    }

    /// Mist's documented default: 5,000 calls/hour, 250 reserved for a human.
    #[must_use]
    pub fn mist_default() -> Self {
        Self::new(5_000, 250)
    }

    fn standard_cap(&self) -> u32 {
        self.hourly_limit.saturating_sub(self.human_reserve)
    }

    fn reset_if_elapsed(window: &mut Window) {
        if window.started_at.elapsed() >= WINDOW {
            window.started_at = Instant::now();
            window.used = 0;
        }
    }

    fn status_locked(&self, window: &Window) -> BudgetStatus {
        BudgetStatus {
            hourly_limit: self.hourly_limit,
            human_reserve: self.human_reserve,
            used: window.used,
            remaining_standard: self.standard_cap().saturating_sub(window.used),
            remaining_reserved: self.hourly_limit.saturating_sub(window.used),
        }
    }

    /// Current headroom without consuming any of it.
    #[must_use]
    pub fn status(&self) -> BudgetStatus {
        let mut window = self.window.lock().expect("rate limit window lock poisoned");
        Self::reset_if_elapsed(&mut window);
        self.status_locked(&window)
    }

    /// Reserve one call against the budget for the given priority, or deny it.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExhausted`] when the pool available to `priority` is spent.
    pub fn try_acquire(&self, priority: CallPriority) -> Result<BudgetStatus, BudgetExhausted> {
        let mut window = self.window.lock().expect("rate limit window lock poisoned");
        Self::reset_if_elapsed(&mut window);

        let cap = match priority {
            CallPriority::Standard => self.standard_cap(),
            CallPriority::Reserved => self.hourly_limit,
        };
        if window.used >= cap {
            return Err(BudgetExhausted);
        }
        window.used += 1;
        Ok(self.status_locked(&window))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_calls_are_denied_once_the_non_reserved_pool_is_spent() {
        let budget = RateLimitBudget::new(10, 3);

        // Standard may use up to hourly_limit - human_reserve = 7 calls.
        for _ in 0..7 {
            assert!(budget.try_acquire(CallPriority::Standard).is_ok());
        }
        let denied = budget.try_acquire(CallPriority::Standard);
        assert_eq!(denied, Err(BudgetExhausted));

        // The reserve is untouched by Standard exhaustion.
        let status = budget.status();
        assert_eq!(status.used, 7);
        assert_eq!(status.remaining_standard, 0);
        assert_eq!(status.remaining_reserved, 3);
    }

    #[test]
    fn reserved_headroom_stays_available_after_standard_is_exhausted() {
        let budget = RateLimitBudget::new(10, 3);
        for _ in 0..7 {
            budget
                .try_acquire(CallPriority::Standard)
                .expect("standard call");
        }
        assert!(budget.try_acquire(CallPriority::Standard).is_err());

        // A human-priority caller can still draw down the reserve.
        for _ in 0..3 {
            assert!(budget.try_acquire(CallPriority::Reserved).is_ok());
        }
        // Now the entire hourly budget, reserve included, is spent.
        assert_eq!(
            budget.try_acquire(CallPriority::Reserved),
            Err(BudgetExhausted)
        );
        assert_eq!(
            budget.try_acquire(CallPriority::Standard),
            Err(BudgetExhausted)
        );
    }

    #[test]
    fn status_reports_headroom_without_consuming_it() {
        let budget = RateLimitBudget::new(10, 3);
        let before = budget.status();
        assert_eq!(before.remaining_standard, 7);
        assert_eq!(before.remaining_reserved, 10);

        budget.try_acquire(CallPriority::Standard).expect("call");
        let after = budget.status();
        assert_eq!(after.used, 1);
        assert_eq!(after.remaining_standard, 6);
        assert_eq!(after.remaining_reserved, 9);

        // status() itself is read-only.
        let again = budget.status();
        assert_eq!(again.used, 1);
    }

    #[test]
    fn window_resets_after_an_hour_elapses() {
        let budget = RateLimitBudget::new(2, 1);
        budget
            .try_acquire(CallPriority::Standard)
            .expect("first call");
        assert!(budget.try_acquire(CallPriority::Standard).is_err());

        // Simulate the hour elapsing by rewinding the recorded window start.
        {
            let mut window = budget.window.lock().expect("lock");
            window.started_at = Instant::now() - Duration::from_secs(3601);
        }

        assert!(budget.try_acquire(CallPriority::Standard).is_ok());
    }

    #[test]
    fn human_reserve_is_clamped_to_the_hourly_limit() {
        let budget = RateLimitBudget::new(5, 100);
        let status = budget.status();
        assert_eq!(status.human_reserve, 5);
        assert_eq!(status.remaining_standard, 0);
        assert_eq!(status.remaining_reserved, 5);
    }
}
