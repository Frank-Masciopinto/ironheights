declare module 'picomatch' {
  interface PicomatchOptions {
    dot?: boolean;
  }
  type Matcher = (value: string) => boolean;
  function picomatch(globs: string | string[], options?: PicomatchOptions): Matcher;
  export default picomatch;
}
