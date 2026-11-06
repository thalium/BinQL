/*
 * String literals whose bytes would break a TRAP `stringliterals(id, "...")`
 * row if the extractor did not escape them: a bare `"` terminates the field
 * (TRAP reader rejects the line -> the whole enclosing function is dropped),
 * `\` starts an escape, and `\t` / `\n` / `\r` / other control bytes are not
 * literal in a TRAP string. `(` `)` `,` `;` `=` `*` are TRAP-structural but
 * only matter unquoted -- included to prove the quoting holds.
 *
 * Each literal is kept live via strlen so Hex-Rays emits a distinct cot_str.
 */
#include <string.h>

int main(void)
{
    /* double quote + backslash + the classic delimiter-confusion payload */
    const char *quotes   = "q=\" and \\\" and end\\";
    /* single quotes (harmless inside a "..." field, but people try it) */
    const char *apostr    = "it's a 'trap', don't you 'think'?";
    /* whitespace control bytes */
    const char *ws         = "tab[\t]nl[\n]cr[\r]end";
    /* low control bytes -> exercise the \uXXXX branch of the escaper */
    const char *ctrl       = "ctrl[\x01\x02\x1f]end";
    /* TRAP-structural characters, must survive verbatim */
    const char *trapchars  = "struct( a , b ) ; x = y * z";
    /* printf specifiers + literal percent */
    const char *fmt        = "100%% done: %s %d %p";
    /* non-ASCII UTF-8 (escaper keeps these literal) */
    const char *utf8       = "caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x92\xa9";

    return (int)(strlen(quotes) + strlen(apostr) + strlen(ws) + strlen(ctrl)
               + strlen(trapchars) + strlen(fmt) + strlen(utf8));
}
