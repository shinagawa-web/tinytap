#!/usr/bin/env bash
# 文体チェック: 記事から「AIっぽい機械的なクセ」を検出する。
# shinagawa-web/blog-articles の scripts/check-style.sh を移植。
#
# 使い方:
#   scripts/check-style.sh [file.md ...]
#   引数が無ければ README.md と site/content/**/*.md を全部チェックする。
#
# 判定（全ファイル共通）:
#   ❌ frontmatter 以外の水平線 ---                    → 要修正（exit 1）
#   ❌ 行頭ラベル・箇条書き先頭以外の文中太字           → 要修正（exit 1）
#   ❌ 箇条書き5項目以上の連続                         → 要修正（exit 1）
#
# 判定（日本語記事 draft/** のみ）:
#   ❌ 行頭の「ラベル：説明」形式（向いている場面：など） → 要修正（exit 1）
#   ❌ 「〜することができ」冗長表現                     → 要修正（exit 1）
#   ❌ 「活用する」                                    → 要修正（exit 1）
#   ❌ 見出しのですます調                              → 要修正（exit 1）
#
# 判定（英語記事 devto/** のみ、tinytapではREADME.md・site/content/**が該当）:
#   ❌ leverage / utilize                              → 要修正（exit 1）
#   ❌ seamlessly                                     → 要修正（exit 1）
#   ❌ can be used to                                 → 要修正（exit 1）
#   ❌ in conclusion / in summary / to summarize      → 要修正（exit 1）
#   ❌ it's worth noting / it is important to note    → 要修正（exit 1）
#   ❌ 行頭の英語ラベル（Note: / Best for: など）      → 要修正（exit 1）
#   ❌ 見出し末尾のピリオド                            → 要修正（exit 1）
#   ❌ emダッシュ（—）                                → 要修正（exit 1）
#
# CI（.github/workflows/style-check.yml）と pre-push フック（scripts/pre-push）の
# 両方からこのスクリプトを呼ぶ。ロジックはここ一箇所に集約する。
set -uo pipefail

files=()
if [ "$#" -gt 0 ]; then
  for f in "$@"; do
    case "$f" in
      draft/*.md|README.md|site/content/*.md) files+=("$f") ;;
    esac
  done
else
  while IFS= read -r f; do
    files+=("$f")
  done < <({ [ -f README.md ] && echo README.md; find site/content -name '*.md' 2>/dev/null; } | sort)
fi

hard_fail=0

for file in "${files[@]:-}"; do
  [ -n "${file:-}" ] || continue
  [ -f "$file" ] || continue

  # 1) frontmatter 以外の水平線 ---（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  セクション区切りの水平線 --- は使わない（frontmatter を除く）"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    $0=="---" { print NR }
  ' "$file")

  # 2) 文中の太字（行頭ラベル・箇条書き先頭以外）（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  文中の太字強調。太字は行頭ラベル・箇条書き先頭のみ許可"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    /\*\*/ {
      line = $0
      sub(/^[[:space:]]*(([-*>]|[0-9]+\.)[[:space:]]+)?/, "", line)
      if (line !~ /^\*\*/) print NR
    }
  ' "$file")

  # --- 日本語記事（draft/**）のみ ---
  case "$file" in draft/*)

  # 3) 行頭の「ラベル：説明」形式（要修正）
  #    「向いている場面：xxx」のような機械的ラベルを検出する。
  #    ・コードブロック・frontmatter・見出し・表・リストは除外
  #    ・「：」前にスペース・括弧・句読点があれば文中の語句説明なのでスキップ
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  行頭ラベル形式（「ラベル：説明」）は使わない。前後の文に溶け込ませる"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /^[#|*>]/ { next }
    /^[-]/ { next }
    /^[0-9]+\. / { next }
    {
      pos = index($0, "：")
      if (pos == 0) next
      label = substr($0, 1, pos - 1)
      if (label ~ /[ \t（）、。・]/) next
      if (length(label) == 0) next
      print NR
    }
  ' "$file")

  # 4) 「〜することができ」冗長表現（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  「〜することができ」は「〜できる」に書き換える"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /することができ/ { print NR }
  ' "$file")

  # 5) 「活用する」（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  「活用する」は具体的な動詞に置き換える"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /活用する/ { print NR }
  ' "$file")

  # 6) 見出しのですます調（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  見出しにですます調は使わない"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    /^#+ .*(ます|です)。?$/ { print NR }
  ' "$file")

  esac
  # --- /日本語記事ここまで ---

  # 7) 箇条書き5項目以上の連続（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  箇条書きは4項目以内にする（5項目目）"
    hard_fail=1
  done < <(awk '
    BEGIN { count=0 }
    /^```/ { fence = !fence; count=0; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { count=0; next }
    /^[[:space:]]*[-*+] |^[[:space:]]*[0-9]+\. / { count++; if (count == 5) print NR; next }
    { count=0 }
  ' "$file")

  # --- 英語記事（README.md・site/content/**）のみ ---
  case "$file" in README.md|site/content/*)

  # 8) leverage / utilize（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  \"leverage\"/\"utilize\" は \"use\" に書き換える"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /[Ll]everage[sd]?|[Ll]everaging|[Uu]tilize[sd]?|[Uu]tilizing/ { print NR }
  ' "$file")

  # 9) seamlessly（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  \"seamlessly\" は中身のない修飾語。削除するか具体的に書く"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /[Ss]eamlessly/ { print NR }
  ' "$file")

  # 10) can be used to（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  \"can be used to\" は冗長。動詞を直接使う"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /can be used to/ { print NR }
  ' "$file")

  # 11) in conclusion / in summary / to summarize（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  まとめ語（in conclusion / in summary / to summarize）は使わない"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /[Ii]n conclusion|[Ii]n summary|[Tt]o summarize|[Tt]o sum up/ { print NR }
  ' "$file")

  # 12) it's worth noting / it is important to note（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  ヘッジ語（it's worth noting など）は削除して事実を直接書く"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /[Ii]t.s worth noting|[Ii]t is (worth|important to) note|[Ii]t is important to note/ { print NR }
  ' "$file")

  # 13) 行頭の英語ラベル（Note: / Best for: / When to use: など）（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  行頭ラベル形式（\"Label:\"）は使わない。前後の文に溶け込ませる"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /^[#|*>]/ { next }
    /^[-]/ { next }
    /^[0-9]+\. / { next }
    /^https?:/ { next }
    {
      pos = index($0, ":")
      if (pos == 0) next
      next_char = substr($0, pos + 1, 1)
      if (next_char != " " && next_char != "") next   # "::" (Test::Nginx など) を除外
      label = substr($0, 1, pos - 1)
      if (label ~ /[ ].*[ ]/) next   # 2つ以上のスペース区切り語があれば文の一部
      if (length(label) == 0 || length(label) > 20) next
      if (label !~ /^[A-Za-z]/) next
      if (label ~ /[.()\[\]{}\/]/) next
      print NR
    }
  ' "$file")

  # 14) 見出し末尾のピリオド（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  見出しにピリオドは付けない"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    /^#+ .*\.$/ { print NR }
  ' "$file")

  # 15) emダッシュ（要修正）
  while IFS= read -r ln; do
    [ -n "$ln" ] || continue
    echo "❌ $file:$ln  emダッシュ（—）は使わない。文を分けるか句読点で書き換える"
    hard_fail=1
  done < <(awk '
    /^```/ { fence = !fence; next }
    fence { next }
    NR==1 && $0=="---" { fm=1; next }
    fm==1 && $0=="---" { fm=2; next }
    fm==1 { next }
    /—/ { print NR }
  ' "$file")

  esac
  # --- /英語記事ここまで ---
done

if [ "$hard_fail" -ne 0 ]; then
  echo ""
  echo "要修正の指摘があります。上記のエラーを確認して修正してください。"
  exit 1
fi

exit 0
