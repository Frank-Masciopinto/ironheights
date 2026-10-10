/**
 * Record the status and return only after stdout and stderr have accepted
 * every buffered byte.
 *
 * `process.exit()` flushes with a synchronous write. A full pipe (64 KiB on
 * Linux) returns EAGAIN and the rest of the buffer is dropped, so a piped
 * report larger than that was cut off. Waiting for `drain` lets a slow reader
 * take the whole report. The interval keeps the process alive because the
 * stdio handles are unref'd.
 */
export function finishCommand(code: number): void {
  process.exitCode = code;
  const pending = [process.stdout, process.stderr].filter(streamNeedsDrain);
  if (pending.length === 0) return;
  const keepAlive = setInterval(() => undefined, 1000);
  let remaining = pending.length;
  const finished = (): void => {
    remaining -= 1;
    if (remaining > 0) return;
    clearInterval(keepAlive);
  };
  for (const stream of pending) {
    let settled = false;
    const onDone = (): void => {
      if (settled) return;
      settled = true;
      stream.off('drain', onDone);
      stream.off('error', onDone);
      finished();
    };
    stream.on('drain', onDone);
    stream.on('error', onDone);
    if (!streamNeedsDrain(stream)) onDone();
  }
}

function streamNeedsDrain(stream: NodeJS.WriteStream): boolean {
  return stream.writableLength > 0 || stream.writableNeedDrain === true;
}
