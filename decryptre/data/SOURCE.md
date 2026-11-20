# Bundled trigram table

`trigrams.txt` holds aggregate counts of three-letter sequences, used only by
the simple-substitution solver to judge which candidate plaintext reads most
like English. It contains no text from the source book -- only counts such as
`the 31254`.

- Source: *Pride and Prejudice* by Jane Austen, Project Gutenberg eBook #1342
  (<https://www.gutenberg.org/ebooks/1342>), a public-domain work in the
  United States.
- Derived: lowercased letters only (`a`-`z`), spaces and punctuation removed,
  every overlapping three-letter window counted once.
- Retrieved: 2026-11-20 (one-time generation at build time).

Frequency statistics like these are facts about the text, not a copy of it.
They are committed so DecryptRE stays fully offline at runtime.

## Regenerating

Any large English plaintext works. For example:

```python
from collections import Counter

text = open("book.txt", encoding="utf-8", errors="ignore").read().lower()
letters = "".join(ch for ch in text if "a" <= ch <= "z")
counts = Counter(letters[i:i + 3] for i in range(len(letters) - 2))
for trigram, count in counts.most_common():
    print(trigram, count)
```

Keep the output small (tens of thousands of lines at most); large tables make
the package slower to import without improving results much.
