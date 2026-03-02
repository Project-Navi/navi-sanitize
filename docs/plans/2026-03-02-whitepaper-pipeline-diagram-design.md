# Whitepaper Pipeline Diagram Design

**Date:** 2026-03-02
**Status:** Approved

## Goal

Add a single TikZ pipeline flow diagram to Section 4 (Pipeline Design) of the whitepaper. Academic/arXiv style — one clear figure, maximum impact, zero decoration.

## Design

### Placement

Section 4, between the introductory paragraph and Table 1. The diagram gives visual architecture; the table provides the specification detail.

### Layout

Horizontal left-to-right flow. Six rounded boxes connected by arrows.

Each box contains:
- Stage number (bold, small)
- Operation name (e.g., "Null strip", "Invisible strip")

### Visual Encoding

- **Stages 1-5:** NaviBlue filled boxes with white text — these are the universal pipeline stages
- **Stage 6 (Escaper):** Dashed border, no fill — signals "optional/pluggable"
- **Stage 5 annotation:** Small label below or above indicating "conditional" (only fires if Stage 4 changed)
- **Arrows:** Simple `->` with stealth tips between boxes
- **Font:** `\footnotesize`, compact enough to fit `\textwidth` in one row

### Caption

"Figure 1: The six-stage sanitization pipeline. Stages 1--5 are universal; Stage 6 is a caller-supplied escaper. Stage 5 runs only when Stage 4 replaces homoglyphs."

### Package Requirements

- `tikz` only (no additional dependencies)

### What Stays

Table 1 remains unchanged — it has the "What It Does" column the diagram intentionally omits.

### Text Change

The Section 4 introductory sentence references "Figure 1" alongside the table.

## Not Doing

- No callout boxes
- No comparison table
- No performance charts
- No title block redesign
