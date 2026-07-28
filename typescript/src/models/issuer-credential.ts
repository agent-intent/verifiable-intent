/** Layer 1: Issuer SD-JWT credential model. */

import type { CnfClaim, JsonObject } from './constraints.js';

export interface IssuerCredentialInit {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  vct?: string;
  aud?: string | null;
  cnfJwk?: JsonObject;
  panLastFour?: string;
  scheme?: string;
  cardId?: string | null;
  email?: string | null;
}

/** Layer 1 Issuer SD-JWT: binds user identity to a public key. */
export class IssuerCredential {
  iss: string;
  sub: string;
  iat: number;
  exp: number;
  vct: string;
  aud: string | null;
  cnfJwk: JsonObject;
  panLastFour: string;
  scheme: string;
  cardId: string | null;
  email: string | null;

  constructor(init: IssuerCredentialInit) {
    this.iss = init.iss;
    this.sub = init.sub;
    this.iat = init.iat;
    this.exp = init.exp;
    this.vct = init.vct ?? 'https://credentials.mastercard.com/card';
    this.aud = init.aud ?? null;
    this.cnfJwk = init.cnfJwk ?? {};
    this.panLastFour = init.panLastFour ?? '';
    this.scheme = init.scheme ?? '';
    this.cardId = init.cardId ?? null;
    this.email = init.email ?? null;
  }

  /** Non-SD claims for the JWT payload; `_sd`/`_sd_alg` are added during issuance. */
  toJSON(): JsonObject {
    const d: JsonObject = {
      iss: this.iss,
      sub: this.sub,
      iat: this.iat,
      exp: this.exp,
      vct: this.vct,
      cnf: { jwk: this.cnfJwk } satisfies CnfClaim,
    };
    if (this.aud) d.aud = this.aud;
    d.pan_last_four = this.panLastFour;
    d.scheme = this.scheme;
    if (this.cardId !== null) d.card_id = this.cardId;
    return d;
  }
}
