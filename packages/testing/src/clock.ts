export interface Clock {
  now(): Date;
}

export function fixedClock(at: Date | string): Clock {
  const fixed = new Date(at);
  return {
    now: () => new Date(fixed.getTime()),
  };
}
