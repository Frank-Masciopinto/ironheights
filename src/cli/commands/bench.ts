import { UsageError } from '../../core/errors.ts';
import { runBench } from '../../../bench/run.ts';

export async function runBenchCommand(options: {
  corpusDir?: string;
  external?: string;
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
}): Promise<number> {
  const env = options.env ?? process.env;
  const corpus = options.corpusDir || env.IH_CORPUS_DIR;
  if (!corpus) throw new UsageError('bench requires a corpus directory');
  const report = await runBench({
    corpusDir: corpus,
    ...(options.external ? { externalPath: options.external } : {}),
  });
  const write = options.stdout ?? ((text: string) => process.stdout.write(text));
  write(
    `skills: ${report.skills}\nreview recall: ${report.reviewOrWorse.recall.toFixed(3)}\nblock recall: ${report.block.recall.toFixed(3)}\n`,
  );
  return 0;
}
