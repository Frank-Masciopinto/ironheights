export class IronheightsError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode: number) {
    super(message);
    this.name = new.target.name;
    this.exitCode = exitCode;
  }
}

export class UsageError extends IronheightsError {
  constructor(message: string) {
    super(message, 64);
  }
}

export class InternalError extends IronheightsError {
  constructor(message: string) {
    super(message, 70);
  }
}

/** Network failure or a rejected signature. The command stops and does not trust the data. */
export class NetworkError extends IronheightsError {
  constructor(message: string) {
    super(message, 70);
  }
}
