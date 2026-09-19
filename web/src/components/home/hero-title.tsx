const LINE_1 = ["Know", "before", "you"];
const COMMAND = "npm install.";

const WORD_START_MS = 200;
const WORD_STEP_MS = 150;
const TYPE_START_MS = 1050;
const TYPE_STEP_MS = 70;

/**
 * Line one: each word rises out from behind an invisible line, one after another.
 * Line two: typed out character by character like a command, ending on a blinking caret.
 */
export function HeroTitle() {
  return (
    <h1 className="text-balance text-[clamp(2.8rem,8vw,6rem)] font-bold leading-[1.02] tracking-[-0.05em]">
      {LINE_1.map((w, i) => (
        <span key={w} className="mask-word mr-[0.24em]">
          <span style={{ animationDelay: `${WORD_START_MS + i * WORD_STEP_MS}ms` }}>{w}</span>
        </span>
      ))}
      <br />
      <span>
        <span className="sr-only">{COMMAND}</span>
        {[...COMMAND].map((ch, i) => {
          const delay = TYPE_START_MS + i * TYPE_STEP_MS;
          const last = i === COMMAND.length - 1;
          return ch === " " ? (
            <span key={i} aria-hidden className="tchar" style={{ animationDelay: `${delay}ms`, width: "0.24em" }}>
              {" "}
            </span>
          ) : (
            <span
              key={i}
              aria-hidden
              className={last ? "tchar tchar-last text-fade" : "tchar text-fade"}
              style={{ animationDelay: `${delay}ms`, ["--d" as string]: `${delay}ms` }}
            >
              {ch}
            </span>
          );
        })}
      </span>
    </h1>
  );
}
