const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const INTERVAL_MS = 80;

/** A minimal polling spinner. Falls back to one line per update when stdout isn't a TTY (CI, pipes). */
export class Spinner {
  private timer: NodeJS.Timeout | undefined;
  private frameIndex = 0;
  private text = "";
  private readonly tty = process.stdout.isTTY === true;

  start(text: string): void {
    this.text = text;
    if (!this.tty) {
      process.stdout.write(`${text}\n`);
      return;
    }
    this.render();
    this.timer = setInterval(() => this.render(), INTERVAL_MS);
  }

  update(text: string): void {
    this.text = text;
    if (!this.tty) process.stdout.write(`${text}\n`);
  }

  stop(finalText?: string): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
    if (this.tty) process.stdout.write("\r\x1b[2K");
    if (finalText) process.stdout.write(`${finalText}\n`);
  }

  private render(): void {
    process.stdout.write(`\r\x1b[2K${FRAMES[this.frameIndex]} ${this.text}`);
    this.frameIndex = (this.frameIndex + 1) % FRAMES.length;
  }
}
