use engine::{verify, Fact, Net, Observation, VerifyOptions};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub struct MusOptions {
    pub slack: usize,
    pub max_states: usize,
}

impl MusOptions {
    pub fn for_observation(obs: &Observation) -> Self {
        MusOptions {
            slack: obs.records.len() + 4,
            max_states: 200_000,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MusResult {
    pub facts: Vec<Fact>,
    pub oracle_calls: usize,
    pub minimal: bool,
    pub relaxation_accepts: bool,
}

struct Oracle<'a> {
    net: &'a Net,
    obs: &'a Observation,
    options: MusOptions,
    calls: usize,
}

impl Oracle<'_> {
    fn accepts(&mut self, keep: &BTreeSet<Fact>) -> bool {
        self.calls += 1;
        let mut restricted = self.obs.restrict(keep);
        for plane in restricted.planes.values_mut() {
            plane.complete = false;
        }
        let options = VerifyOptions {
            bound: restricted.records.len() + self.options.slack,
            slack: self.options.slack,
            max_states: self.options.max_states,
        };
        verify(self.net, &restricted, options).accepted()
    }

    fn quickxplain(
        &mut self,
        background: &BTreeSet<Fact>,
        delta_used: bool,
        candidates: &[Fact],
    ) -> Vec<Fact> {
        if delta_used && !self.accepts(background) {
            return Vec::new();
        }
        if candidates.len() == 1 {
            return candidates.to_vec();
        }
        let split = candidates.len() / 2;
        let (left, right) = candidates.split_at(split);

        let mut with_left = background.clone();
        with_left.extend(left.iter().cloned());
        let first = self.quickxplain(&with_left, !left.is_empty(), right);

        let mut with_first = background.clone();
        with_first.extend(first.iter().cloned());
        let second = self.quickxplain(&with_first, !first.is_empty(), left);

        let mut out = first;
        out.extend(second);
        out
    }

    fn shrink(&mut self, core: Vec<Fact>) -> (Vec<Fact>, bool) {
        let mut current: BTreeSet<Fact> = core.into_iter().collect();
        loop {
            let mut removed = false;
            for fact in current.iter().cloned().collect::<Vec<Fact>>() {
                let mut candidate = current.clone();
                candidate.remove(&fact);
                if !self.accepts(&candidate) {
                    current = candidate;
                    removed = true;
                }
            }
            if !removed {
                break;
            }
        }
        let minimal = current
            .iter()
            .cloned()
            .collect::<Vec<Fact>>()
            .iter()
            .all(|fact| {
                let mut candidate = current.clone();
                candidate.remove(fact);
                self.accepts(&candidate)
            });
        (current.into_iter().collect(), minimal)
    }
}

pub fn extract(net: &Net, obs: &Observation, options: MusOptions) -> MusResult {
    let mut oracle = Oracle {
        net,
        obs,
        options,
        calls: 0,
    };
    let facts = obs.facts();
    let all: BTreeSet<Fact> = facts.iter().cloned().collect();

    if oracle.accepts(&all) {
        return MusResult {
            facts: Vec::new(),
            oracle_calls: oracle.calls,
            minimal: true,
            relaxation_accepts: true,
        };
    }

    let core = oracle.quickxplain(&BTreeSet::new(), false, &facts);
    let core = if core.is_empty() { facts } else { core };
    let (facts, minimal) = oracle.shrink(core);

    MusResult {
        facts,
        oracle_calls: oracle.calls,
        minimal,
        relaxation_accepts: false,
    }
}
