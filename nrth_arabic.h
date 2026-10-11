#pragma once
/**
 * ============================================================================
 * nrth_arabic.h — Self-contained Arabic Contextual Shaper & BiDi Visual Order
 *                 for Dear ImGui (imstb_truetype)
 * ============================================================================
 * Converts logical UTF-8 strings containing Arabic (U+0600..U+06FF) into
 * shaped Arabic Presentation Forms-B (U+FE70..U+FEFC, including Lam-Alef
 * ligatures U+FEF5..U+FEFC) ordered in visual left-to-right sequence for
 * Dear ImGui's LTR text renderer, while preserving embedded Latin/numeric/
 * printf-format runs and ImGui "##id" suffixes.
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <string>
#include <vector>

struct NrthArabicLetterMap {
    uint32_t unicode;
    uint32_t isolated;
    uint32_t finalForm;
    uint32_t initial;
    uint32_t medial;
    bool     joinsRight; /* connects to preceding letter */
    bool     joinsLeft;  /* connects to following letter */
};

static const NrthArabicLetterMap kNrthArabicLetters[] = {
    { 0x0621, 0xFE80, 0xFE80, 0xFE80, 0xFE80, false, false }, /* ء Hamza */
    { 0x0622, 0xFE81, 0xFE82, 0xFE81, 0xFE82, true,  false }, /* آ Alef Madda */
    { 0x0623, 0xFE83, 0xFE84, 0xFE83, 0xFE84, true,  false }, /* أ Alef Hamza Above */
    { 0x0624, 0xFE85, 0xFE86, 0xFE85, 0xFE86, true,  false }, /* ؤ Waw Hamza */
    { 0x0625, 0xFE87, 0xFE88, 0xFE87, 0xFE88, true,  false }, /* إ Alef Hamza Below */
    { 0x0626, 0xFE89, 0xFE8A, 0xFE8B, 0xFE8C, true,  true  }, /* ئ Yeh Hamza */
    { 0x0627, 0xFE8D, 0xFE8E, 0xFE8D, 0xFE8E, true,  false }, /* ا Alef */
    { 0x0628, 0xFE8F, 0xFE90, 0xFE91, 0xFE92, true,  true  }, /* ب Beh */
    { 0x0629, 0xFE93, 0xFE94, 0xFE93, 0xFE94, true,  false }, /* ة Teh Marbuta */
    { 0x062A, 0xFE95, 0xFE96, 0xFE97, 0xFE98, true,  true  }, /* ت Teh */
    { 0x062B, 0xFE99, 0xFE9A, 0xFE9B, 0xFE9C, true,  true  }, /* ث Theh */
    { 0x062C, 0xFE9D, 0xFE9E, 0xFE9F, 0xFEA0, true,  true  }, /* ج Jeem */
    { 0x062D, 0xFEA1, 0xFEA2, 0xFEA3, 0xFEA4, true,  true  }, /* ح Hah */
    { 0x062E, 0xFEA5, 0xFEA6, 0xFEA7, 0xFEA8, true,  true  }, /* خ Khah */
    { 0x062F, 0xFEA9, 0xFEAA, 0xFEA9, 0xFEAA, true,  false }, /* د Dal */
    { 0x0630, 0xFEAB, 0xFEAC, 0xFEAB, 0xFEAC, true,  false }, /* ذ Thal */
    { 0x0631, 0xFEAD, 0xFEAE, 0xFEAD, 0xFEAE, true,  false }, /* ر Reh */
    { 0x0632, 0xFEAF, 0xFEB0, 0xFEAF, 0xFEB0, true,  false }, /* ز Zain */
    { 0x0633, 0xFEB1, 0xFEB2, 0xFEB3, 0xFEB4, true,  true  }, /* س Seen */
    { 0x0634, 0xFEB5, 0xFEB6, 0xFEB7, 0xFEB8, true,  true  }, /* ش Sheen */
    { 0x0635, 0xFEB9, 0xFEBA, 0xFEBB, 0xFEBC, true,  true  }, /* ص Sad */
    { 0x0636, 0xFEBD, 0xFEBE, 0xFEBF, 0xFEC0, true,  true  }, /* ض Dad */
    { 0x0637, 0xFEC1, 0xFEC2, 0xFEC3, 0xFEC4, true,  true  }, /* ط Tah */
    { 0x0638, 0xFEC5, 0xFEC6, 0xFEC7, 0xFEC8, true,  true  }, /* ظ Zah */
    { 0x0639, 0xFEC9, 0xFECA, 0xFECB, 0xFECC, true,  true  }, /* ع Ain */
    { 0x063A, 0xFECD, 0xFECE, 0xFECF, 0xFED0, true,  true  }, /* غ Ghain */
    { 0x0640, 0x0640, 0x0640, 0x0640, 0x0640, true,  true  }, /* ـ Tatweel */
    { 0x0641, 0xFED1, 0xFED2, 0xFED3, 0xFED4, true,  true  }, /* ف Feh */
    { 0x0642, 0xFED5, 0xFED6, 0xFED7, 0xFED8, true,  true  }, /* ق Qaf */
    { 0x0643, 0xFED9, 0xFEDA, 0xFEDB, 0xFEDC, true,  true  }, /* ك Kaf */
    { 0x0644, 0xFEDD, 0xFEDE, 0xFEDF, 0xFEE0, true,  true  }, /* ل Lam */
    { 0x0645, 0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4, true,  true  }, /* م Meem */
    { 0x0646, 0xFEE5, 0xFEE6, 0xFEE7, 0xFEE8, true,  true  }, /* ن Noon */
    { 0x0647, 0xFEE9, 0xFEEA, 0xFEEB, 0xFEEC, true,  true  }, /* ه Heh */
    { 0x0648, 0xFEED, 0xFEEE, 0xFEED, 0xFEEE, true,  false }, /* و Waw */
    { 0x0649, 0xFEEF, 0xFEF0, 0xFEEF, 0xFEF0, true,  false }, /* ى Alef Maksura */
    { 0x064A, 0xFEF1, 0xFEF2, 0xFEF3, 0xFEF4, true,  true  }, /* ي Yeh */
};

static inline const NrthArabicLetterMap *Nrth_FindArabicLetter(uint32_t cp)
{
    for (size_t i = 0; i < sizeof(kNrthArabicLetters) / sizeof(kNrthArabicLetters[0]); ++i) {
        if (kNrthArabicLetters[i].unicode == cp) {
            return &kNrthArabicLetters[i];
        }
    }
    return nullptr;
}

static inline bool Nrth_IsArabicDiacritic(uint32_t cp)
{
    return (cp >= 0x064B && cp <= 0x065F) || cp == 0x0670;
}

static inline bool Nrth_IsArabicChar(uint32_t cp)
{
    return (cp >= 0x0600 && cp <= 0x06FF) ||
           (cp >= 0xFB50 && cp <= 0xFDFF) ||
           (cp >= 0xFE70 && cp <= 0xFEFF);
}

static inline uint32_t Nrth_LamAlefLigature(uint32_t alefCp, bool connectPrev)
{
    switch (alefCp) {
        case 0x0622: return connectPrev ? 0xFEF6u : 0xFEF5u; /* لآ */
        case 0x0623: return connectPrev ? 0xFEF8u : 0xFEF7u; /* لأ */
        case 0x0625: return connectPrev ? 0xFEFAu : 0xFEF9u; /* لإ */
        case 0x0627: return connectPrev ? 0xFEFCu : 0xFEFBu; /* لا */
        default:     return 0;
    }
}

static inline void Nrth_DecodeUTF8(const char *s, size_t len, std::vector<uint32_t> &out)
{
    out.clear();
    size_t i = 0;
    while (i < len) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80) {
            out.push_back(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < len) {
            uint32_t cp = ((uint32_t)(c & 0x1F) << 6) |
                          ((uint32_t)((unsigned char)s[i + 1] & 0x3F));
            out.push_back(cp);
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < len) {
            uint32_t cp = ((uint32_t)(c & 0x0F) << 12) |
                          ((uint32_t)((unsigned char)s[i + 1] & 0x3F) << 6) |
                          ((uint32_t)((unsigned char)s[i + 2] & 0x3F));
            out.push_back(cp);
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < len) {
            uint32_t cp = ((uint32_t)(c & 0x07) << 18) |
                          ((uint32_t)((unsigned char)s[i + 1] & 0x3F) << 12) |
                          ((uint32_t)((unsigned char)s[i + 2] & 0x3F) << 6) |
                          ((uint32_t)((unsigned char)s[i + 3] & 0x3F));
            out.push_back(cp);
            i += 4;
        } else {
            out.push_back(c);
            ++i;
        }
    }
}

static inline void Nrth_AppendUTF8(std::string &out, uint32_t cp)
{
    if (cp < 0x80) {
        out.push_back((char)cp);
    } else if (cp < 0x800) {
        out.push_back((char)(0xC0 | (cp >> 6)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back((char)(0xE0 | (cp >> 12)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    } else {
        out.push_back((char)(0xF0 | (cp >> 18)));
        out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    }
}

static inline bool Nrth_IsLtrCoreChar(uint32_t cp)
{
    return (cp >= 'A' && cp <= 'Z') ||
           (cp >= 'a' && cp <= 'z') ||
           (cp >= '0' && cp <= '9') ||
           cp == '%' || cp == '_' || cp == '\\' || cp == '@';
}

static inline bool Nrth_IsLtrConnector(uint32_t cp)
{
    return cp == '.' || cp == '-' || cp == '+' || cp == '/' || cp == ':' || cp == ' ';
}

static inline uint32_t Nrth_MirrorBracket(uint32_t cp)
{
    switch (cp) {
        case '(': return ')';
        case ')': return '(';
        case '[': return ']';
        case ']': return '[';
        case '<': return '>';
        case '>': return '<';
        case '{': return '}';
        case '}': return '{';
        default:  return cp;
    }
}

static inline std::string Nrth_ShapeArabicSegment(const char *str, size_t len)
{
    std::vector<uint32_t> cps;
    Nrth_DecodeUTF8(str, len, cps);

    bool hasArabic = false;
    for (uint32_t cp : cps) {
        if (Nrth_IsArabicChar(cp)) {
            hasArabic = true;
            break;
        }
    }
    if (!hasArabic) {
        return std::string(str, len);
    }

    /* Strip optional Arabic diacritics to keep clean joining */
    std::vector<uint32_t> clean;
    clean.reserve(cps.size());
    for (uint32_t cp : cps) {
        if (!Nrth_IsArabicDiacritic(cp)) {
            clean.push_back(cp);
        }
    }

    /* Step 1: Logical contextual shaping + Lam-Alef ligatures */
    std::vector<uint32_t> shaped;
    shaped.reserve(clean.size());
    bool prevJoinsLeft = false;

    for (size_t i = 0; i < clean.size(); ++i) {
        uint32_t cur = clean[i];
        const NrthArabicLetterMap *curMap = Nrth_FindArabicLetter(cur);
        if (!curMap) {
            shaped.push_back(cur);
            prevJoinsLeft = false;
            continue;
        }

        /* Check Lam-Alef ligature */
        if (cur == 0x0644 && i + 1 < clean.size()) {
            uint32_t nextCp = clean[i + 1];
            uint32_t lig = Nrth_LamAlefLigature(nextCp, prevJoinsLeft);
            if (lig != 0) {
                shaped.push_back(lig);
                prevJoinsLeft = false;
                ++i; /* consumed Alef */
                continue;
            }
        }

        bool nextJoinsRight = false;
        if (curMap->joinsLeft && i + 1 < clean.size()) {
            const NrthArabicLetterMap *nextMap = Nrth_FindArabicLetter(clean[i + 1]);
            if (nextMap && nextMap->joinsRight) {
                nextJoinsRight = true;
            }
        }

        bool connectPrev = prevJoinsLeft && curMap->joinsRight;
        bool connectNext = curMap->joinsLeft && nextJoinsRight;

        uint32_t glyph = curMap->isolated;
        if (connectPrev && connectNext) {
            glyph = curMap->medial;
        } else if (connectPrev && !connectNext) {
            glyph = curMap->finalForm;
        } else if (!connectPrev && connectNext) {
            glyph = curMap->initial;
        } else {
            glyph = curMap->isolated;
        }

        shaped.push_back(glyph);
        prevJoinsLeft = connectNext;
    }

    /* Step 2: BiDi visual ordering (reverse RTL line while keeping LTR runs intact) */
    std::vector<bool> isLtr(shaped.size(), false);
    for (size_t i = 0; i < shaped.size(); ++i) {
        if (Nrth_IsLtrCoreChar(shaped[i])) {
            isLtr[i] = true;
        }
    }
    /* Allow connectors (., -, /, :) between two LTR chars (e.g. "%.2f", "v4.0", "C:\NVX") */
    for (size_t i = 1; i + 1 < shaped.size(); ++i) {
        if (!isLtr[i] && Nrth_IsLtrConnector(shaped[i]) && isLtr[i - 1] && isLtr[i + 1]) {
            isLtr[i] = true;
        }
    }

    /* Reverse entire shaped array for RTL visual display, mirroring brackets in RTL */
    std::vector<uint32_t> visual(shaped.size());
    std::vector<bool>     visLtr(shaped.size());
    size_t n = shaped.size();
    for (size_t i = 0; i < n; ++i) {
        uint32_t cp = shaped[n - 1 - i];
        bool ltr    = isLtr[n - 1 - i];
        if (!ltr) {
            cp = Nrth_MirrorBracket(cp);
        }
        visual[i] = cp;
        visLtr[i] = ltr;
    }

    /* Restore forward order for contiguous LTR sub-runs */
    size_t idx = 0;
    while (idx < n) {
        if (!visLtr[idx]) {
            ++idx;
            continue;
        }
        size_t end = idx + 1;
        while (end < n && visLtr[end]) {
            ++end;
        }
        /* Reverse visual[idx..end-1] back to LTR */
        size_t l = idx, r = end - 1;
        while (l < r) {
            uint32_t tmp = visual[l];
            visual[l] = visual[r];
            visual[r] = tmp;
            ++l;
            --r;
        }
        idx = end;
    }

    std::string out;
    out.reserve(len + 16);
    for (uint32_t cp : visual) {
        Nrth_AppendUTF8(out, cp);
    }
    return out;
}

static inline std::string Nrth_ShapeArabicUTF8(const char *utf8)
{
    if (!utf8 || !utf8[0]) {
        return std::string();
    }
    /* Preserve ImGui "##" ID suffix untouched at the end */
    const char *hashPos = strstr(utf8, "##");
    size_t visLen = hashPos ? (size_t)(hashPos - utf8) : strlen(utf8);
    if (visLen == 0) {
        return std::string(utf8);
    }

    /* Process line by line in case of multiline text */
    std::string result;
    size_t start = 0;
    while (start <= visLen) {
        const char *nl = (const char *)memchr(utf8 + start, '\n', visLen - start);
        size_t segLen = nl ? (size_t)(nl - (utf8 + start)) : (visLen - start);
        result += Nrth_ShapeArabicSegment(utf8 + start, segLen);
        if (nl) {
            result.push_back('\n');
            start += segLen + 1;
        } else {
            break;
        }
    }

    if (hashPos) {
        result += hashPos;
    }
    return result;
}
