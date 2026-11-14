"""Present unverified COSE/CWT fields and explicit CBOR representation comparisons."""

import matplotlib.pyplot as plt
import numpy as np
from IPython.display import display
from matplotlib.ticker import MaxNLocator
from matplotlib.colors import ListedColormap
from vgi_notebooks import finish, prose

STATUS_COLORS = {
    "Elapsed expiry": "#a85337",
    "Within review window": "#c57b40",
    "Beyond deadline": "#267358",
    "Expiry missing": "#73889a",
    "No decoded claims": "#8e81a5",
    "Malformed CBOR": "#665b58",
    "Missing input": "#aab8b0",
}
CLAIMS_SOURCE = "Source: synthetic unverified COSE/CWT envelopes · native VGI CBOR v0.7.1 · fixed UTC audit clock"
IDENTITY_SOURCE = "Source: eight authored CBOR items + four separate controls · native VGI CBOR v0.7.1 · no external tokens"


def validate_horizon(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 90:
        raise ValueError("HORIZON_DAYS must be a whole number from 1 through 90.")


def validate_rebuild(value):
    if type(value) is not bool:
        raise ValueError("REBUILD_FROM_JSON must be True or False.")


def claims_checks(checks):
    display(checks)
    assert (checks.violations == 0).all(), (
        "Decoded fields or inventory preservation changed."
    )
    prose(
        f"All **{len(checks)} checks pass**, including exact decoded expiry timestamps and the zero-byte signature placeholders. The decoder exposes those placeholders successfully; the result establishes structure, not authenticity."
    )


def inventory_chart(summary, HORIZON_DAYS):
    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    y = np.arange(len(summary))
    bars = ax.barh(
        y,
        summary.records,
        color=[STATUS_COLORS[s] for s in summary.disposition],
        height=0.63,
    )
    ax.bar_label(bars, padding=5, fmt="%.0f")
    ax.set(
        yticks=y,
        yticklabels=summary.disposition,
        xlabel="Input records",
        ylabel="",
        xlim=(0, max(1, summary.records.max()) + 1),
    )
    ax.invert_yaxis()
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "Keep undated and undecodable inputs in view",
        f"Audit: 2026-11-14 00:00 UTC · forward review window: {HORIZON_DAYS} days",
        CLAIMS_SOURCE,
        name="01-claim-dispositions",
    )
    counts = summary.set_index("disposition").records
    undated = int(
        counts[
            ["Expiry missing", "No decoded claims", "Malformed CBOR", "Missing input"]
        ].sum()
    )
    prose(
        f"The inventory retains **{int(summary.records.sum())} records**. **{int(counts['Within review window'])}** have a claimed future expiry inside the selected window, **{int(counts['Elapsed expiry'])}** have elapsed, and **{undated}** cannot be placed on the expiry timeline. Those undated records remain separate review categories."
    )


def date_chart(dated, HORIZON_DAYS):
    display(dated)
    y = np.arange(len(dated))
    fig, ax = plt.subplots(figsize=(10.8, 6.8))
    ax.axvspan(0, HORIZON_DAYS, color="#c57b40", alpha=0.11)
    ax.axvline(0, color="#52675a", linewidth=1)
    ax.axvline(
        HORIZON_DAYS,
        color="#c57b40",
        linestyle="--",
        linewidth=1.5,
        label=f"Deadline: +{HORIZON_DAYS} days",
    )
    for i, row in enumerate(dated.itertuples()):
        color = STATUS_COLORS[row.disposition]
        ax.plot([0, row.days_from_audit], [i, i], color=color, alpha=0.35, linewidth=2)
        ax.scatter(row.days_from_audit, i, color=color, s=65, zorder=3)
        ax.annotate(
            f"{row.days_from_audit:+.0f} d",
            (row.days_from_audit, i),
            xytext=(7 if row.days_from_audit >= 0 else -7, 0),
            ha="left" if row.days_from_audit >= 0 else "right",
            textcoords="offset points",
            va="center",
            fontsize=9,
            color=color,
        )
    ax.set(
        yticks=y,
        yticklabels=dated.subject,
        xlabel="Days from the fixed UTC audit instant",
        ylabel="",
        xlim=(
            min(-8, dated.days_from_audit.min() - 5),
            max(HORIZON_DAYS, dated.days_from_audit.max()) + 12,
        ),
    )
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    ax.legend(loc="upper right", frameon=True)
    finish(
        fig,
        "A longer window changes the queue, not the dates",
        f"Unverified claimed expiries · {len(dated)} dated records · {HORIZON_DAYS}-day horizon",
        CLAIMS_SOURCE,
        name="02-claimed-dates",
    )
    prose(
        f"The dated subset contains **{len(dated)} records**, from **{dated.days_from_audit.min():+.0f}** to **{dated.days_from_audit.max():+.0f} days** relative to the audit clock. Moving the deadline recolors existing points; it does not alter the envelopes, decoded timestamps or missing-input categories."
    )


def control_finding(controls):
    display(controls)
    by_name = controls.set_index("label")
    assert bool(by_name.loc["Duplicate key", "single_item_valid"])
    assert not bool(by_name.loc["Duplicate key", "strict_ok"])
    prose(
        "The duplicate-key control is **one parseable item** but fails the worker's stricter "
        "map-key check. Truncation and trailing bytes fail the single-item check; NULL stays unknown. "
        "A non-NULL JSON projection is therefore not a substitute for the input-quality decision. "
        "The eight identity-study items pass both checks and stay separate from these four controls."
    )


def projection_finding(projection):
    display(projection)
    assert (projection.json_view == projection.decode_struct).all()
    assert projection.decode_type.eq("VARCHAR").all()
    prose(
        "All eight rows return **the same JSON text from `to_json` and `decode(...,'struct')`**. "
        "Despite that mode name, this release returns VARCHAR; it does not restore a typed CBOR value. "
        "The diagnostic column distinguishes byte strings from text, tags from bare values, and integer "
        "map keys from text keys. Keep original bytes when those distinctions matter."
    )


def tag_finding(tag_rows):
    display(tag_rows)
    prose(
        "Only the tagged item reports **tag 1 at `$`**, and `untag(...,1)` returns **`[1]`** "
        "for it versus **`[]`** for the bare integer. `untag` returns JSON values found under a tag; "
        "it does not return a rewritten CBOR blob. Tag inspection is structural, not validation of a real timestamp source."
    )


def identity_chart(pair_frame, summary, rebuild):
    display(pair_frame)
    columns = ["original_equal", "archive_equal", "json_equal"]
    labels = ["Original bytes", "Selected archive bytes", "JSON projection"]
    matrix = pair_frame[columns].to_numpy(dtype=int)
    fig, ax = plt.subplots(figsize=(11.7, 6.4))
    ax.imshow(
        matrix,
        cmap=ListedColormap(["#e5ebe7", "#267358"]),
        vmin=0,
        vmax=1,
        aspect="auto",
    )
    ax.set_xticks(range(3), labels)
    ax.set_yticks(range(len(pair_frame)), pair_frame.pair_label)
    ax.tick_params(axis="y", labelsize=10)
    ax.grid(False)
    ax.set_xticks(np.arange(-0.5, 3, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(pair_frame), 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=3)
    ax.tick_params(which="minor", bottom=False, left=False)
    for y, row in enumerate(matrix):
        for x, v in enumerate(row):
            ax.text(
                x,
                y,
                "Equal" if v else "Different",
                ha="center",
                va="center",
                fontsize=11,
                color="white" if v else "#253d31",
            )
    mode = "JSON reconstruction" if rebuild else "core canonical bytes"
    finish(
        fig,
        "Equal JSON does not establish CBOR identity",
        f"Selected archive: {mode} · compare each deliberately paired source representation",
        IDENTITY_SOURCE,
        name="03-identity-comparisons",
    )
    r = summary.iloc[0]
    prose(
        f"The **{int(r.input_rows)} source items** contain **{int(r.original_distinct)} distinct original byte strings**. "
        f"The selected archive has **{int(r.archive_distinct)} distinct byte strings**, while the JSON view has "
        f"only **{int(r.json_distinct)} distinct values**. JSON reconstruction changes **{int(r.rebuild_changes)} "
        "of eight core-normalized source encodings** even before choosing it as the archive. "
        f"The selected archive differs from core-normalized source bytes in **{int(r.archive_changes)} rows**. "
        "These counts describe the authored cases, not every CBOR value or an application-wide equivalence rule."
    )


def byte_chart(sizes, rebuild):
    display(sizes)
    y = np.arange(len(sizes))
    fig, ax = plt.subplots(figsize=(11.7, 7.2))
    for offset, col, label, color in [
        (-0.18, "source_bytes", "Original bytes", "#aab8b0"),
        (0.18, "archive_bytes", "Selected archive", "#456fba"),
    ]:
        bars = ax.barh(y + offset, sizes[col], height=0.32, label=label, color=color)
        ax.bar_label(bars, padding=4, fmt="%.0f", fontsize=9)
    ax.set_yticks(y, sizes.label)
    ax.tick_params(axis="y", labelsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Encoded bytes per item")
    ax.set_xlim(0, max(sizes.source_bytes.max(), sizes.archive_bytes.max()) + 2)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right")
    finish(
        fig,
        "Byte count is separate from information preservation",
        ("JSON reconstruction" if rebuild else "Core canonical archive")
        + " · all eight original byte strings remain retained",
        IDENTITY_SOURCE,
        name="04-encoded-byte-counts",
    )
    prose(
        f"The selected archive contains **{int(sizes.archive_bytes.sum())} bytes** across these eight rows, "
        f"compared with **{int(sizes.source_bytes.sum())} original bytes**. A shorter or longer result is not "
        "evidence of preserved types. Even deterministic re-encoding can change original bytes; never replace "
        "signed input with normalized bytes and assume an existing signature still applies."
    )


def identity_checks(checks):
    display(checks)
    assert checks.passed.notna().all() and checks.passed.astype(bool).all()
    prose(
        f"**All {len(checks)} relationship checks passed.** Original inputs stay retained; the archive choice "
        "changes only the explicitly selected derived representation."
    )
