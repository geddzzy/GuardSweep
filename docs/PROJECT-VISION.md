# Project Vision

This document keeps the direction for `guard-sweep` explicit while HostIntent consolidation is underway.

## Repository Identity

- Repo: `guard-sweep`
- Working title: `GuardSweep`
- Current repository type: defensive monitoring prototype
- Current role: source of reusable background monitoring patterns

## Current Framing

GuardSweep is a useful endpoint-monitoring prototype, but it should no longer expand as an equal flagship next to HostIntent.

Its most valuable role now is to preserve and refine reusable ideas around:

- long-running monitors
- process monitoring loops
- network monitoring loops
- persistence monitoring loops
- alert emission patterns

that can later migrate into HostIntent.

## Strategic Focus

- Keep GuardSweep honest as a monitoring prototype, not a broad product claim.
- Preserve monitoring ideas that can be lifted into HostIntent later.
- Avoid major new product-scope expansion that increases overlap with HostIntent.

## Practical Direction

Near-term work in this repo should focus on:

- stabilizing useful monitor patterns
- documenting operational tradeoffs
- keeping tests runnable
- making eventual migration into HostIntent easier

## Planning Rule

If a planned GuardSweep feature would be more valuable as part of HostIntent’s long-term agent architecture, document it here but implement it in HostIntent instead.
