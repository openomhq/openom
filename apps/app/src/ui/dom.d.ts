export type DomChild = Node | string | number | boolean | null | undefined | readonly DomChild[];
export type DomProps = Readonly<Record<string, unknown>> | null;

export function h<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  props?: DomProps,
  ...children: DomChild[]
): HTMLElementTagNameMap[Tag];
export function h(tag: string, props?: DomProps, ...children: DomChild[]): HTMLElement;

export function svg(tag: string, props?: DomProps, ...children: DomChild[]): SVGElement;
export function mount<T extends Node>(target: Element, node: T): T;
export function initials(person: { given?: string; surname?: string } | null | undefined): string;
export function fullName(
  person: { given?: string; surname?: string } | null | undefined,
  fallback?: string,
): string;
export function toast(message: string): void;
