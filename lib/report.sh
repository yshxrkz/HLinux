# shellcheck shell=bash
#
# report.sh - write the results of the last audit as Markdown, HTML or JSON.
#
# Part of HLinux (harden-audit.sh). Sourced, not executed.
#
# The report is the ONLY file the audit ever writes, and only when asked to
# with --report. It is created with mode 600 (it names accounts and
# weaknesses), via a temp file in the same directory that is then renamed
# into place, so a symlink planted at the report path cannot redirect the
# write somewhere else.

# Filled in by the caller before writing a report.
REPORT_MODE="audit"     # audit | harden
REPORT_HOST=""
REPORT_DATE=""          # human-readable
REPORT_DATE_ISO=""      # ISO 8601, UTC
REPORT_USER=""
SCORE_BEFORE=""         # harden mode: score before any fix was applied
GRADE_BEFORE=""

# report_format_for FILE [FORMAT] - pick md | html | json (from the extension
# when FORMAT is empty). Returns 1 for an unknown format.
report_format_for() {
    local file=$1 fmt=${2:-}
    if [[ -z $fmt ]]; then
        case ${file,,} in
            *.md|*.markdown) fmt=md ;;
            *.html|*.htm)    fmt=html ;;
            *.json)          fmt=json ;;
        esac
    fi
    case $fmt in
        md|markdown) echo md ;;
        html)        echo html ;;
        json)        echo json ;;
        *)           return 1 ;;
    esac
}

# write_report FILE FORMAT - render the report and move it into place.
write_report() {
    local file=$1 fmt=$2 dir tmp
    dir=$(dirname -- "$file")
    if [[ ! -d $dir ]]; then
        echo "Cannot write report: directory $dir does not exist." >&2
        return 1
    fi
    if [[ -d $file ]]; then
        echo "Cannot write report: $file is a directory." >&2
        return 1
    fi
    tmp=$(umask 077 && mktemp "$dir/.harden-audit-report.XXXXXX") || {
        echo "Cannot write report: unable to create a file in $dir." >&2
        return 1
    }
    case $fmt in
        md)   render_markdown > "$tmp" ;;
        html) render_html > "$tmp" ;;
        json) render_json > "$tmp" ;;
    esac
    if ! chmod 600 "$tmp" || ! mv -f -- "$tmp" "$file"; then
        rm -f -- "$tmp"
        echo "Cannot write report to $file." >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------

# The replacements are quoted on purpose: since bash 5.2 an unquoted "&" in
# ${var//pattern/replacement} stands for the matched text (patsub_replacement).
html_escape() {
    local s=$1
    s=${s//&/"&amp;"}
    s=${s//</"&lt;"}
    s=${s//>/"&gt;"}
    s=${s//\"/"&quot;"}
    s=${s//\'/"&#39;"}
    printf '%s' "$s"
}

# Markdown table cell: escape pipes, turn newlines into <br>.
md_cell() {
    local s=$1
    s=${s//|/\\|}
    s=${s//$'\n'/<br>}
    printf '%s' "$s"
}

json_string() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    # Drop any other control characters, which JSON does not allow raw.
    if [[ $s == *[[:cntrl:]]* ]]; then
        s=$(printf '%s' "$s" | tr -d '\000-\037')
    fi
    printf '"%s"' "$s"
}

# ---------------------------------------------------------------------------
# Shared data
# ---------------------------------------------------------------------------

# Categories in registry order, each listed once.
report_categories() {
    local id cat seen=" "
    for id in "${CONTROL_IDS[@]}"; do
        cat=${CTL_CAT[$id]}
        [[ $seen == *" $cat "* ]] && continue
        seen+="$cat "
        printf '%s\n' "$cat"
    done
}

# category_counts CATEGORY - prints "PASS FAIL SKIP" for that category.
category_counts() {
    local id p=0 f=0 s=0
    for id in "${R_IDS[@]}"; do
        [[ ${CTL_CAT[$id]} == "$1" ]] || continue
        case ${R_STATUS[$id]} in
            PASS) p=$((p + 1)) ;;
            FAIL) f=$((f + 1)) ;;
            *)    s=$((s + 1)) ;;
        esac
    done
    printf '%d %d %d' "$p" "$f" "$s"
}

score_text() {
    if [[ -n $SCORE ]]; then
        printf '%s/100 (grade %s)' "$SCORE" "$GRADE"
    else
        printf 'n/a'
    fi
}

# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

readonly MD_FENCE='```'
readonly MD_TICK='`'

md_status() {
    case $1 in
        PASS) printf '✅ PASS' ;;
        FAIL) printf '❌ FAIL' ;;
        *)    printf '⚪ SKIP' ;;
    esac
}

render_markdown() {
    local id cat p f s
    printf '# Linux hardening report: %s\n\n' "$(md_cell "$REPORT_HOST")"
    printf '| | |\n|---|---|\n'
    printf '| **Host** | %s |\n' "$(md_cell "$REPORT_HOST")"
    printf '| **OS** | %s (kernel %s) |\n' "$(md_cell "$OS_NAME")" "$(uname -r)"
    printf '| **Date** | %s |\n' "$REPORT_DATE"
    printf '| **Run as** | %s |\n' "$(md_cell "$REPORT_USER")"
    printf '| **Tool** | harden-audit.sh %s (%s mode) |\n\n' "$VERSION" "$REPORT_MODE"

    printf '## Hardening score: %s\n\n' "$(score_text)"
    if [[ -n $SCORE ]]; then
        printf '%s%s%s %s/100\n\n' "$MD_TICK" "$(score_bar "$SCORE")" "$MD_TICK" "$SCORE"
    fi
    if [[ -n $SCORE_BEFORE ]]; then
        printf 'Before hardening: **%s/100 (grade %s)** → after: **%s**\n\n' \
            "$SCORE_BEFORE" "$GRADE_BEFORE" "$(score_text)"
    fi
    printf '**%d passed**, **%d failed**, **%d skipped** out of %d controls. ' \
        "$N_PASS" "$N_FAIL" "$N_SKIP" $((N_PASS + N_FAIL + N_SKIP))
    printf 'The score weights each control by severity (high = 3, medium = 2, low = 1) and leaves skipped controls out.\n\n'

    printf '## Results by category\n\n'
    printf '| Category | Passed | Failed | Skipped |\n|---|---:|---:|---:|\n'
    while IFS= read -r cat; do
        read -r p f s < <(category_counts "$cat")
        printf '| %s | %d | %d | %d |\n' "$cat" "$p" "$f" "$s"
    done < <(report_categories)

    printf '\n## All controls\n\n'
    printf '| Status | ID | Severity | Control |\n|---|---|---|---|\n'
    for id in "${R_IDS[@]}"; do
        printf '| %s | %s | %s | %s |\n' "$(md_status "${R_STATUS[$id]}")" "$id" \
            "${CTL_SEV[$id]}" "$(md_cell "${R_TITLE[$id]}")"
    done

    local any=0
    for id in "${R_IDS[@]}"; do
        [[ ${R_STATUS[$id]} == FAIL ]] || continue
        if ((any == 0)); then
            printf '\n## Findings\n'
            any=1
        fi
        printf '\n### ❌ %s: %s\n\n' "$id" "$(md_cell "${R_TITLE[$id]}")"
        printf '*Severity: %s · Category: %s*\n\n' "${CTL_SEV[$id]}" "${CTL_CAT[$id]}"
        printf '**What was found**\n\n%stext\n%s\n%s\n\n' "$MD_FENCE" "${R_DETAIL[$id]}" "$MD_FENCE"
        printf '**Why it matters:** %s\n\n' "${CTL_WHY[$id]}"
        if [[ -n ${R_FIX[$id]} ]]; then
            printf '**How to fix**\n\n%stext\n%s\n%s\n' "$MD_FENCE" "${R_FIX[$id]}" "$MD_FENCE"
        fi
    done

    any=0
    for id in "${R_IDS[@]}"; do
        [[ ${R_STATUS[$id]} == SKIP ]] || continue
        ((any == 0)) && printf '\n## Skipped\n\n' && any=1
        printf -- '- **%s** %s: %s\n' "$id" "$(md_cell "${R_TITLE[$id]}")" "$(md_cell "${R_DETAIL[$id]}")"
    done

    any=0
    for id in "${R_IDS[@]}"; do
        [[ ${R_STATUS[$id]} == PASS ]] || continue
        ((any == 0)) && printf '\n## Passed\n\n' && any=1
        printf -- '- ✅ **%s** %s: %s\n' "$id" "$(md_cell "${R_TITLE[$id]}")" "$(md_cell "${R_DETAIL[$id]}")"
    done

    printf '\n---\n\n*Generated by harden-audit.sh %s. Controls are loosely based on the CIS Benchmarks; this is not a full CIS assessment.*\n' "$VERSION"
}

# ---------------------------------------------------------------------------
# HTML (self-contained: inline CSS, no JavaScript, no external resources)
# ---------------------------------------------------------------------------

html_badge() {
    printf '<span class="badge %s">%s</span>' "${1,,}" "$1"
}

render_html() {
    local id cat p f s ring='var(--fail)' title
    title="Hardening report: $(html_escape "$REPORT_HOST")"
    if [[ -n $SCORE ]]; then
        if ((SCORE >= 80)); then ring='var(--pass)'
        elif ((SCORE >= 60)); then ring='var(--skip)'
        fi
    fi
    printf '%s\n' '<!doctype html>' '<html lang="en">' '<head>' \
        '<meta charset="utf-8">' \
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
    printf '<title>%s</title>\n' "$title"
    printf '%s\n' '<style>' \
        ':root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5b6475;--border:#dde1e8;--pass:#1f8a4c;--fail:#c62f3a;--skip:#a46b00;--code:#f0f2f5}' \
        '@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b1f27;--text:#e6e9ef;--muted:#9aa3b2;--border:#2c323d;--pass:#3fbf73;--fail:#ef5b67;--skip:#e0a93a;--code:#232833}}' \
        '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}' \
        'main{max-width:980px;margin:0 auto;padding:32px 16px 48px}h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:32px 0 12px}' \
        '.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin:12px 0}' \
        '.hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap}.hero>div:last-child{flex:1;min-width:260px}.ring{--p:0;width:132px;height:132px;border-radius:50%;flex:none;display:grid;place-items:center;background:conic-gradient(var(--c) calc(var(--p)*1%),var(--border) 0)}' \
        '.ring div{width:104px;height:104px;border-radius:50%;background:var(--card);display:grid;place-items:center;text-align:center}.ring b{font-size:2rem;line-height:1}.ring small{color:var(--muted)}' \
        'table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle}th{color:var(--muted);font-weight:600;font-size:.85rem}th.n,td.n{text-align:right;font-variant-numeric:tabular-nums}' \
        '.badge{display:inline-block;min-width:3.6em;text-align:center;font-size:.75rem;font-weight:700;padding:2px 8px;border-radius:999px;color:#fff}.badge.pass{background:var(--pass)}.badge.fail{background:var(--fail)}.badge.skip{background:var(--skip)}' \
        '.sev{font-size:.8rem;color:var(--muted)}.finding{border-left:4px solid var(--fail)}.finding h3{margin:0 0 4px;font-size:1.05rem}' \
        'pre{background:var(--code);border-radius:6px;padding:10px 12px;white-space:pre-wrap;word-break:break-word;margin:6px 0 10px;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}' \
        '.label{font-weight:600;margin-top:10px}details summary{cursor:pointer;font-weight:600}ul.passed{margin:8px 0 0;padding-left:20px}ul.passed li{margin:4px 0}' \
        'dl{display:grid;grid-template-columns:auto 1fr;gap:2px 16px;margin:0}dt{color:var(--muted)}dd{margin:0}footer{margin-top:40px;font-size:.85rem;color:var(--muted)}' \
        '</style>' '</head>' '<body>' '<main>'
    printf '<h1>%s</h1>\n<p class="muted">Linux hardening %s report generated by harden-audit.sh %s</p>\n' \
        "$title" "$REPORT_MODE" "$VERSION"

    printf '<section class="card hero">\n'
    printf '<div class="ring" style="--p:%s;--c:%s"><div><span><b>%s</b><br><small>grade %s</small></span></div></div>\n' \
        "${SCORE:-0}" "$ring" "${SCORE:-n/a}" "$GRADE"
    printf '<div><dl>\n'
    printf '<dt>Host</dt><dd>%s</dd>\n' "$(html_escape "$REPORT_HOST")"
    printf '<dt>OS</dt><dd>%s (kernel %s)</dd>\n' "$(html_escape "$OS_NAME")" "$(html_escape "$(uname -r)")"
    printf '<dt>Date</dt><dd>%s</dd>\n' "$(html_escape "$REPORT_DATE")"
    printf '<dt>Run as</dt><dd>%s</dd>\n' "$(html_escape "$REPORT_USER")"
    printf '<dt>Results</dt><dd><b>%d</b> passed, <b>%d</b> failed, <b>%d</b> skipped</dd>\n' "$N_PASS" "$N_FAIL" "$N_SKIP"
    if [[ -n $SCORE_BEFORE ]]; then
        printf '<dt>Before hardening</dt><dd>%s/100 (grade %s)</dd>\n' "$SCORE_BEFORE" "$GRADE_BEFORE"
    fi
    printf '</dl>\n<p class="muted">Score = severity-weighted share of passed controls (high 3, medium 2, low 1); skipped controls are excluded.</p></div>\n</section>\n'

    printf '<h2>Results by category</h2>\n<div class="card"><table>\n<tr><th>Category</th><th class="n">Passed</th><th class="n">Failed</th><th class="n">Skipped</th></tr>\n'
    while IFS= read -r cat; do
        read -r p f s < <(category_counts "$cat")
        printf '<tr><td>%s</td><td class="n">%d</td><td class="n">%d</td><td class="n">%d</td></tr>\n' \
            "$(html_escape "$cat")" "$p" "$f" "$s"
    done < <(report_categories)
    printf '</table></div>\n'

    printf '<h2>All controls</h2>\n<div class="card"><table>\n<tr><th>Status</th><th>ID</th><th>Control</th><th>Severity</th></tr>\n'
    for id in "${R_IDS[@]}"; do
        printf '<tr><td>%s</td><td>%s</td><td>%s</td><td class="sev">%s</td></tr>\n' \
            "$(html_badge "${R_STATUS[$id]}")" "$id" "$(html_escape "${R_TITLE[$id]}")" "${CTL_SEV[$id]}"
    done
    printf '</table></div>\n'

    if ((N_FAIL)); then
        printf '<h2>Findings</h2>\n'
        for id in "${R_IDS[@]}"; do
            [[ ${R_STATUS[$id]} == FAIL ]] || continue
            printf '<article class="card finding">\n<h3>%s %s: %s</h3>\n' \
                "$(html_badge FAIL)" "$id" "$(html_escape "${R_TITLE[$id]}")"
            printf '<div class="sev">Severity: %s · Category: %s</div>\n' "${CTL_SEV[$id]}" "$(html_escape "${CTL_CAT[$id]}")"
            printf '<div class="label">What was found</div><pre>%s</pre>\n' "$(html_escape "${R_DETAIL[$id]}")"
            printf '<div class="label">Why it matters</div><p>%s</p>\n' "$(html_escape "${CTL_WHY[$id]}")"
            if [[ -n ${R_FIX[$id]} ]]; then
                printf '<div class="label">How to fix</div><pre>%s</pre>\n' "$(html_escape "${R_FIX[$id]}")"
            fi
            printf '</article>\n'
        done
    fi

    if ((N_SKIP)); then
        printf '<h2>Skipped</h2>\n<div class="card"><ul class="passed">\n'
        for id in "${R_IDS[@]}"; do
            [[ ${R_STATUS[$id]} == SKIP ]] || continue
            printf '<li><b>%s</b> %s: <span class="muted">%s</span></li>\n' \
                "$id" "$(html_escape "${R_TITLE[$id]}")" "$(html_escape "${R_DETAIL[$id]}")"
        done
        printf '</ul></div>\n'
    fi

    if ((N_PASS)); then
        printf '<h2>Passed</h2>\n<div class="card"><details><summary>%d controls passed</summary><ul class="passed">\n' "$N_PASS"
        for id in "${R_IDS[@]}"; do
            [[ ${R_STATUS[$id]} == PASS ]] || continue
            printf '<li>%s <b>%s</b> %s: <span class="muted">%s</span></li>\n' "$(html_badge PASS)" \
                "$id" "$(html_escape "${R_TITLE[$id]}")" "$(html_escape "${R_DETAIL[$id]}")"
        done
        printf '</ul></details></div>\n'
    fi

    printf '<footer>Generated %s by harden-audit.sh %s. Controls are loosely based on the CIS Benchmarks; this is not a full CIS assessment.</footer>\n' \
        "$(html_escape "$REPORT_DATE")" "$VERSION"
    printf '%s\n' '</main>' '</body>' '</html>'
}

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

render_json() {
    local id first=1
    printf '{\n'
    printf '  "tool": "harden-audit.sh",\n  "version": %s,\n  "mode": %s,\n' \
        "$(json_string "$VERSION")" "$(json_string "$REPORT_MODE")"
    printf '  "host": %s,\n  "os": %s,\n  "kernel": %s,\n  "date": %s,\n  "user": %s,\n' \
        "$(json_string "$REPORT_HOST")" "$(json_string "$OS_NAME")" "$(json_string "$(uname -r)")" \
        "$(json_string "$REPORT_DATE_ISO")" "$(json_string "$REPORT_USER")"
    printf '  "score": %s,\n  "grade": %s,\n' "${SCORE:-null}" "$(json_string "$GRADE")"
    if [[ -n $SCORE_BEFORE ]]; then
        printf '  "score_before": %s,\n  "grade_before": %s,\n' "$SCORE_BEFORE" "$(json_string "$GRADE_BEFORE")"
    fi
    printf '  "summary": {"pass": %d, "fail": %d, "skip": %d},\n' "$N_PASS" "$N_FAIL" "$N_SKIP"
    printf '  "controls": ['
    for id in "${R_IDS[@]}"; do
        ((first)) || printf ','
        first=0
        printf '\n    {"id": %s, "title": %s, "category": %s, "severity": %s, "status": %s,\n' \
            "$(json_string "$id")" "$(json_string "${R_TITLE[$id]}")" "$(json_string "${CTL_CAT[$id]}")" \
            "$(json_string "${CTL_SEV[$id]}")" "$(json_string "${R_STATUS[$id]}")"
        printf '     "detail": %s,\n     "fix": %s,\n     "why": %s}' \
            "$(json_string "${R_DETAIL[$id]}")" "$(json_string "${R_FIX[$id]}")" "$(json_string "${CTL_WHY[$id]}")"
    done
    printf '\n  ]\n}\n'
}
