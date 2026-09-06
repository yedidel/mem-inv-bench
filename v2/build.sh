#!/usr/bin/env bash
# Build the paper and FAIL LOUDLY.
#
# Grepping the log for "undefined" is not a build check. A malformed table body
# produced 89 TeX errors while the page count and the undefined-reference count
# both looked fine, and the PDF still rendered, so the defect was invisible to
# everything being watched. This script reports the three things that matter and
# exits non-zero on any of them.
set -u
cd "$(dirname "$0")"

pdflatex -interaction=nonstopmode tops.tex >/dev/null 2>&1
bibtex tops >/dev/null 2>&1
pdflatex -interaction=nonstopmode tops.tex >/dev/null 2>&1
pdflatex -interaction=nonstopmode tops.tex >build.log 2>&1

errors=$(grep -c '^! ' build.log)
undef=$(grep -c 'undefined' build.log)
overfull=$(grep -c 'Overfull \\hbox' build.log)
pages=$(python -c "import fitz,sys;print(len(fitz.open('tops.pdf')))" 2>/dev/null || echo "?")

echo "pages:            $pages / 35"
echo "TeX errors:       $errors"
echo "undefined refs:   $undef"
echo "overfull hboxes:  $overfull"

if [ "$errors" -gt 0 ]; then
  echo
  echo "FIRST ERRORS:"
  grep -n -A3 '^! ' build.log | head -24
fi

if [ "$errors" -gt 0 ] || [ "$undef" -gt 0 ]; then
  echo
  echo "BUILD FAILED"
  exit 1
fi
if [ "$pages" != "?" ] && [ "$pages" -gt 35 ]; then
  echo
  echo "OVER THE 35-PAGE LIMIT"
  exit 1
fi
echo
echo "BUILD CLEAN"
