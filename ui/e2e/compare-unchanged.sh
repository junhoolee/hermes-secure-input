#!/bin/bash
# Criterion 8 of card t_ce4fbc04: the screens this card does not change (one-time code, end screens) look
# exactly as on the baseline commit. Captures the same screens from the baseline bundle and from the current
# build with the same spec (e2e/screenshots.spec.ts, CAPTURE_ONLY=unchanged) and compares SHA-256 per file.
#
# One capture is not always byte-stable: the filled one-time code field on 1280x800 sometimes comes out with
# about 30 border pixels off by 1-2 colour levels, from either bundle. So each side is captured RUNS times
# (default 3). A file counts as the same when some baseline capture and some current capture have the same
# SHA-256. For a file with no common hash the first pair is compared pixel by pixel (e2e/pixel-diff.mjs).
# Writes ui/captures/UNCHANGED.md. Usage (from ui/): bash e2e/compare-unchanged.sh [baseline-commit]
set -euo pipefail
BASE=${1:-f6d33cfacb4be386582d7cd791dc7dedeeea86f4}
RUNS=${RUNS:-3}
UI=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/compare-unchanged.XXXXXX")
if [ -n "${KEEP:-}" ]; then echo "captures kept in $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi

git -C "$UI/.." archive "$BASE" secure_input/static | tar -x -C "$WORK"
cd "$UI"
for i in $(seq 1 "$RUNS"); do
  SCREENSHOTS=1 CAPTURE_ONLY=unchanged CAPTURE_PROTOCOL=1 STATIC_ROOT="$WORK/secure_input/static" CAPTURE_DIR="$WORK/base$i" \
    npx playwright test e2e/screenshots.spec.ts --project=chromium-mobile --project=chromium-desktop --workers=2 >"$WORK/base$i.log" 2>&1
  SCREENSHOTS=1 CAPTURE_ONLY=unchanged CAPTURE_DIR="$WORK/head$i" \
    npx playwright test e2e/screenshots.spec.ts --project=chromium-mobile --project=chromium-desktop --workers=2 >"$WORK/head$i.log" 2>&1
done

hashes() { # side file -> distinct short hashes over all runs, space separated
  for i in $(seq 1 "$RUNS"); do shasum -a 256 <"$WORK/$1$i/$2" | cut -c1-16; done | sort -u | tr '\n' ' ' | sed 's/ $//'
}

HEAD_COMMIT=$(git -C "$UI/.." rev-parse HEAD)
same=0
diff=0
first_same=0
rows=""
for f in "$WORK"/base1/*.png; do
  b=$(basename "$f")
  hb=$(hashes base "$b")
  hh=$(hashes head "$b")
  common=$(comm -12 <(tr ' ' '\n' <<<"$hb" | sort) <(tr ' ' '\n' <<<"$hh" | sort) | head -1)
  [ "$(shasum -a 256 <"$WORK/base1/$b")" = "$(shasum -a 256 <"$WORK/head1/$b")" ] && first_same=$((first_same + 1))
  if [ -n "$common" ]; then
    same=$((same + 1))
    r="같음(공통 \`$common\`)"
  else
    diff=$((diff + 1))
    r="다름: $(node e2e/pixel-diff.mjs "$WORK/base1/$b" "$WORK/head1/$b")"
  fi
  rows+="| \`$b\` | \`${hb// /\`, \`}\` | \`${hh// /\`, \`}\` | $r |"$'\n'
done

{
  echo "# 바뀌지 않는 화면의 캡처 비교"
  echo
  echo "\`bash e2e/compare-unchanged.sh\`가 이 파일을 만든다."
  echo "기준 커밋 \`$BASE\`의 빌드 결과와 비교한 커밋 \`$HEAD_COMMIT\`의 빌드 결과를, 같은 가짜 서버와 같은 시각(2026-11-25 12:00 KST 고정)으로 찍었다."
  echo "기준 쪽은 1판 화면이라 여는 응답의 \`v\`를 1로 주었다. 나머지 내용은 같다."
  echo "비교한 화면은 일회용 코드 입력(빈 칸, 코드 넣음), 일회용 코드 완료, 이미 열린 링크, 제출 시간 지남, 요청 취소다."
  echo "화면 크기는 390x844와 1280x800, 밝기는 light와 dark, 화면 배율은 1이다."
  echo
  echo "같은 쪽을 ${RUNS}번씩 찍었다. 한 번만 찍으면 1280x800의 '코드 넣음' 캡처가 가끔 다르게 나오기 때문이다."
  echo "그때 다른 곳은 코드 입력칸 테두리의 픽셀 30개 안팎이고, 색 차이는 0~255 가운데 1~2다."
  echo "이 흔들림은 기준 쪽과 이번 쪽 모두에서 생긴다. 그래서 기준 쪽 해시 가운데 하나와 이번 쪽 해시 가운데 하나가 같으면 같은 화면으로 판정한다."
  echo
  echo "결과: 같음 ${same}장, 다름 ${diff}장(SHA-256 전체 비교). 첫 번째 쌍만 놓고 보면 ${first_same}장이 같았다."
  echo
  echo "| 파일 | 기준 쪽 SHA-256 앞 16자(서로 다른 값) | 이번 쪽 SHA-256 앞 16자(서로 다른 값) | 결과 |"
  echo "|---|---|---|---|"
  printf '%s' "$rows"
} >"$UI/captures/UNCHANGED.md"
echo "same=$same diff=$diff first_pair_same=$first_same"
