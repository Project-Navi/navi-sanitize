# Character Reference

Complete tables of all characters handled by navi-sanitize's pipeline.

## Invisible Characters (492 total)

### Zero-Width Characters (8)

| Codepoint | Name | Why Stripped |
|-----------|------|-------------|
| U+200B | Zero-width space | Invisible word boundary; breaks token matching |
| U+200C | Zero-width non-joiner | Invisible modifier; evasion in keyword filters |
| U+200D | Zero-width joiner | Invisible modifier; used in emoji but exploited in text |
| U+200E | Left-to-right mark | Invisible directional control |
| U+200F | Right-to-left mark | Invisible directional control |
| U+2060 | Word joiner | Invisible no-break hint; evasion vector |
| U+FEFF | BOM / zero-width no-break space | Byte order mark; invisible at start or middle of string |
| U+180E | Mongolian vowel separator | Invisible separator; historically used for evasion |

### Format and Control Characters (27)

| Codepoint | Name | Why Stripped |
|-----------|------|-------------|
| U+00AD | Soft hyphen | Invisible in most renderers; breaks word matching |
| U+034F | Combining grapheme joiner | Invisible modifier between characters |
| U+2009 | Thin space | Near-invisible space variant |
| U+200A | Hair space | Near-invisible space variant (thinnest) |
| U+2028 | Line separator | Invisible line break; XSS vector in JavaScript |
| U+2029 | Paragraph separator | Invisible paragraph break; XSS vector in JavaScript |
| U+FFF9 | Interlinear annotation anchor | Invisible annotation control |
| U+FFFA | Interlinear annotation separator | Invisible annotation control |
| U+FFFB | Interlinear annotation terminator | Invisible annotation control |
| U+FFFC | Object replacement character | Placeholder for embedded object; invisible in text |
| U+2061 | Function application | Invisible math operator |
| U+2062 | Invisible times | Invisible math operator |
| U+2063 | Invisible separator | Invisible math operator; hides keywords |
| U+2064 | Invisible plus | Invisible math operator |
| U+206A | Inhibit symmetric swapping | Deprecated format control |
| U+206B | Activate symmetric swapping | Deprecated format control |
| U+206C | Inhibit Arabic form shaping | Deprecated format control |
| U+206D | Activate Arabic form shaping | Deprecated format control |
| U+206E | National digit shapes | Deprecated format control |
| U+206F | Nominal digit shapes | Deprecated format control |
| U+2800 | Braille pattern blank | Renders as empty space |
| U+1680 | Ogham space mark | Invisible space variant |
| U+115F | Hangul Choseong filler | Invisible hangul filler |
| U+1160 | Hangul Jungseong filler | Invisible hangul filler |
| U+3164 | Hangul filler | NFKC-normalizes to U+1160; pre-stripped |
| U+FFA0 | Halfwidth hangul filler | NFKC-normalizes to U+1160; pre-stripped |
| U+061C | Arabic letter mark | Invisible directional mark |

### Mongolian Free Variation Selectors (4)

| Codepoint | Name | Why Stripped |
|-----------|------|-------------|
| U+180B | Mongolian FVS one | Invisible glyph modifier; functionally identical to VS1--VS16 |
| U+180C | Mongolian FVS two | Invisible glyph modifier |
| U+180D | Mongolian FVS three | Invisible glyph modifier |
| U+180F | Mongolian FVS four | Invisible glyph modifier |

### Variation Selectors (16)

| Range | Name | Why Stripped |
|-------|------|-------------|
| U+FE00--U+FE0F | VS1--VS16 | Invisible glyph presentation modifiers; alter character display without visible change in most contexts |

### Unicode Tag Block (128)

| Range | Name | Why Stripped |
|-------|------|-------------|
| U+E0000 | Language tag (deprecated) | Deprecated; invisible |
| U+E0001--U+E007F | Tag characters | Invisible ASCII encoding; used in tag smuggling attacks where tokenizers read content that humans cannot see |

### Variation Selector Supplement (240)

| Range | Name | Why Stripped |
|-------|------|-------------|
| U+E0100--U+E01EF | VS17--VS256 | Extended invisible glyph modifiers for CJK ideographic variation |

### Bidirectional Control Characters (9)

| Codepoint | Name | Why Stripped |
|-----------|------|-------------|
| U+202A | Left-to-right embedding | Reorders text display to hide content |
| U+202B | Right-to-left embedding | Reorders text display to hide content |
| U+202C | Pop directional formatting | Terminates bidi override |
| U+202D | Left-to-right override | Forces display direction; hides malicious content |
| U+202E | Right-to-left override | Reverses displayed text order |
| U+2066 | Left-to-right isolate | Isolates text direction; evasion in mixed content |
| U+2067 | Right-to-left isolate | Isolates text direction; evasion in mixed content |
| U+2068 | First strong isolate | Auto-detects direction; unpredictable display |
| U+2069 | Pop directional isolate | Terminates bidi isolate |

### C0 Control Characters (28)

| Range | Why Stripped |
|-------|-------------|
| U+0001--U+0008 | Includes BEL (U+0007), BS (U+0008, terminal overwrite attack) |
| U+000B--U+000C | Vertical tab, form feed |
| U+000E--U+001F | Includes ESC (U+001B, ANSI injection); excludes TAB (U+0009), LF (U+000A), CR (U+000D) |

### C1 Control Characters (32)

| Range | Why Stripped |
|-------|-------------|
| U+0080--U+009F | Includes CSI (U+009B, equivalent to ESC+[) and NEL (U+0085); invisible in all modern contexts |

---

## Homoglyph Map (66 pairs)

### Cyrillic to Latin --- Lowercase (11 pairs)

| Cyrillic | Codepoint | Latin | Visual |
|----------|-----------|-------|--------|
| а | U+0430 | a | а → a |
| е | U+0435 | e | е → e |
| о | U+043E | o | о → o |
| р | U+0440 | p | р → p |
| с | U+0441 | c | с → c |
| у | U+0443 | y | у → y |
| х | U+0445 | x | х → x |
| і | U+0456 | i | і → i |
| ѕ | U+0455 | s | ѕ → s |
| ј | U+0458 | j | ј → j |
| һ | U+04BB | h | һ → h |

### Cyrillic to Latin --- Uppercase (14 pairs)

| Cyrillic | Codepoint | Latin | Visual |
|----------|-----------|-------|--------|
| А | U+0410 | A | А → A |
| В | U+0412 | B | В → B |
| Е | U+0415 | E | Е → E |
| К | U+041A | K | К → K |
| М | U+041C | M | М → M |
| Н | U+041D | H | Н → H |
| О | U+041E | O | О → O |
| Р | U+0420 | P | Р → P |
| С | U+0421 | C | С → C |
| Т | U+0422 | T | Т → T |
| Х | U+0425 | X | Х → X |
| І | U+0406 | I | І → I |
| Ѕ | U+0405 | S | Ѕ → S |
| Ј | U+0408 | J | Ј → J |

### Greek to Latin --- Uppercase (14 pairs)

| Greek | Codepoint | Latin | Visual |
|-------|-----------|-------|--------|
| Α | U+0391 | A | Α → A |
| Β | U+0392 | B | Β → B |
| Ε | U+0395 | E | Ε → E |
| Ζ | U+0396 | Z | Ζ → Z |
| Η | U+0397 | H | Η → H |
| Ι | U+0399 | I | Ι → I |
| Κ | U+039A | K | Κ → K |
| Μ | U+039C | M | Μ → M |
| Ν | U+039D | N | Ν → N |
| Ο | U+039F | O | Ο → O |
| Ρ | U+03A1 | P | Ρ → P |
| Τ | U+03A4 | T | Τ → T |
| Υ | U+03A5 | Y | Υ → Y |
| Χ | U+03A7 | X | Χ → X |

### Greek to Latin --- Lowercase (11 pairs)

| Greek | Codepoint | Latin | Visual |
|-------|-----------|-------|--------|
| α | U+03B1 | a | α → a |
| γ | U+03B3 | y | γ → y |
| ι | U+03B9 | i | ι → i |
| κ | U+03BA | k | κ → k |
| μ | U+03BC | u | μ → u |
| ν | U+03BD | v | ν → v |
| ο | U+03BF | o | ο → o |
| ρ | U+03C1 | p | ρ → p |
| τ | U+03C4 | t | τ → t |
| υ | U+03C5 | u | υ → u |
| ω | U+03C9 | w | ω → w |

### Armenian to Latin (2 pairs)

| Armenian | Codepoint | Latin | Visual |
|----------|-----------|-------|--------|
| Օ | U+0555 | O | Օ → O |
| Ս | U+054D | S | Ս → S |

### Cherokee to Latin (1 pair)

| Cherokee | Codepoint | Latin | Visual |
|----------|-----------|-------|--------|
| Ꭺ | U+13AA | A | Ꭺ → A |

### Cyrillic Extended to Latin (5 pairs)

| Cyrillic | Codepoint | Latin | Visual |
|----------|-----------|-------|--------|
| Ӏ | U+04C0 | I | Ӏ → I |
| ӏ | U+04CF | l | ӏ → l |
| ԁ | U+0501 | d | ԁ → d |
| ԛ | U+051B | q | ԛ → q |
| ԝ | U+051D | w | ԝ → w |

### Latin Extended to Latin (1 pair)

| Character | Codepoint | Latin | Visual |
|-----------|-----------|-------|--------|
| ı | U+0131 | i | ı → i |

### Typographic Replacements (7 pairs)

| Character | Codepoint | Name | Replacement |
|-----------|-----------|------|-------------|
| − | U+2212 | Minus sign | - (hyphen) |
| – | U+2013 | En dash | - (hyphen) |
| — | U+2014 | Em dash | - (hyphen) |
| ' | U+2018 | Left single quote | ' (apostrophe) |
| ' | U+2019 | Right single quote | ' (apostrophe) |
| " | U+201C | Left double quote | " (straight quote) |
| " | U+201D | Right double quote | " (straight quote) |

---

## NFKC Normalization Examples

NFKC (Stage 3) normalizes compatibility forms before homoglyph replacement. Common transformations:

| Input | Codepoint(s) | Output | Category |
|-------|-------------|--------|----------|
| ａ | U+FF41 | a | Fullwidth lowercase |
| Ａ | U+FF21 | A | Fullwidth uppercase |
| ０ | U+FF10 | 0 | Fullwidth digit |
| ﬁ | U+FB01 | fi | Ligature |
| ﬀ | U+FB00 | ff | Ligature |
| ² | U+00B2 | 2 | Superscript |
| ⁿ | U+207F | n | Superscript |
| ① | U+2460 | 1 | Circled |
| 𝑎 | U+1D44E | a | Math italic |
| 𝐀 | U+1D400 | A | Math bold |
