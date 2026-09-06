export interface Clock {
  now(): Date;
}

export function fixedClock(at: Date | string): Clock {
  const fixed = new Date(at);
  return {
    now: () => new Date(fixed.getTime()),
  };
}

export interface MutableClock extends Clock {
  set(at: Date | string): void;
}

/** Like `fixedClock`, but advanceable — for tests that need to simulate time passing (e.g. a token expiring) without a real wall-clock wait. */
export function mutableClock(at: Date | string): MutableClock {
  let current = new Date(at);
  return {
    now: () => new Date(current.getTime()),
    set: (next) => {
      current = new Date(next);
    },
  };
}
