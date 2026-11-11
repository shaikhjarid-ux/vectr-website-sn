# disguised-filenames

Flags file names built to look like something else.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `filename.double-extension` | medium | a document or media extension (pdf doc docx xls xlsx txt jpg jpeg png gif mp3 mp4) followed by an executable one |
| `filename.control-chars` | medium | right-to-left override and other bidirectional control characters |
| `filename.archive-executable` | medium | an archive and an executable extension combined, in either order (Setup.exe.zip) |
| `filename.homoglyph` | low | Latin letters mixed with Cyrillic or Greek letters in the file name stem |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

The last decoded path segment of every http(s) URL reference, file-name query parameter values, and the download attribute of anchors and areas.

## Blind spots

Names that only look different in a font (for example the digit 0 and the letter O) are not detected. Only Cyrillic and Greek look-alikes are checked. Names inside archives are never seen.

## Confidence

Medium for the structural rules, low for the homoglyph rule.

## False positives

Genuine names with several dots (report.final.pdf is fine; report.pdf.zip is not flagged by double-extension). Multilingual names that deliberately mix scripts can trigger the homoglyph rule at low severity.
