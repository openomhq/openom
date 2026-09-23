export interface Endpoint {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: EventListenerOrEventListenerObject): void;
  removeEventListener(type: 'message', listener: EventListenerOrEventListenerObject): void;
  start?(): void;
}

type RemoteMember<Value> = Value extends (...args: infer Args) => infer Result
  ? (...args: Args) => Promise<Awaited<Result>>
  : Value extends object
    ? Remote<Value>
    : Promise<Value>;

export type Remote<Value> = {
  [Key in keyof Value]: RemoteMember<Value[Key]>;
};

export function expose(value: unknown, endpoint?: Endpoint): void;
export function proxy<Value extends object>(value: Value): Value;
export function wrap<Value>(endpoint: Endpoint): Remote<Value>;
