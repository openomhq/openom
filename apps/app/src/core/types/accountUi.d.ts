import type { AccountProbe, AccountSessionState } from './accountSession.js';
import type { AuthCapabilities, AuthSignUpResult, PasswordCredentials } from './session.js';

export type AccountUiScreen =
  | 'overview'
  | 'signIn'
  | 'signUp'
  | 'confirmationRequired'
  | 'restore'
  | 'conflict';

export type AccountUiOperation = 'signUp' | 'signIn' | 'signOut' | 'enableSync';
export type AccountUiNotice = 'confirmationRequired';
export type AccountUiDiscovery = 'unknown' | 'unregistered' | 'registered';

export interface AccountUiState {
  readonly screen: AccountUiScreen | null;
  readonly busy: AccountUiOperation | null;
  readonly error: string;
  readonly notice: AccountUiNotice | null;
  readonly discovery: AccountUiDiscovery;
}

export interface AccountUiAccount {
  state(): AccountSessionState;
  probe(): Promise<AccountProbe>;
  enableSync(): Promise<AccountSessionState>;
}

export interface AccountUiAuth {
  signUp(credentials: PasswordCredentials): Promise<AuthSignUpResult>;
  signIn(credentials: PasswordCredentials): Promise<void>;
  signOut(): Promise<void>;
}

export interface AccountUiActionsOptions {
  readonly account: AccountUiAccount;
  readonly auth: AccountUiAuth;
  readonly onChange?: (state: AccountUiState) => void;
  readonly errorText: (error: unknown) => string;
  readonly logError: (operation: AccountUiOperation, error: unknown) => unknown;
}

export interface AccountViewHost {
  readonly account: { state(): AccountSessionState };
  readonly auth: { capabilities(): AuthCapabilities };
  accountUiState(): Readonly<AccountUiState>;
  showAccountView(screen?: AccountUiScreen): void;
  closeAccountView(): void;
  doSignUp(email: string, password: string): Promise<unknown>;
  doSignIn(email: string, password: string): Promise<unknown>;
  doSignOut(): Promise<unknown>;
  doEnableSync(): Promise<unknown>;
}
