/** Layer 1: Issuer credential creation. */

import { createDisclosure, createSdArray, generateSalt } from '../crypto/disclosure.js';
import { createSdJwt, SdJwt } from '../crypto/sd-jwt.js';
import type { Es256Jwk, IssuanceHeader } from '../crypto/signing.js';
import { IssuerCredential } from '../models/issuer-credential.js';
import type { IssueOptions } from './options.js';

/**
 * Create a Layer 1 Issuer SD-JWT.
 *
 * One selectively disclosable claim (email only). Always visible: iss, sub,
 * iat, exp, vct, cnf, pan_last_four, scheme (+ optional aud, card_id).
 */
export async function createLayer1(
  credential: IssuerCredential,
  issuerPrivateJwk: Es256Jwk,
  opts: IssueOptions = {},
): Promise<SdJwt> {
  const kid = opts.kid ?? 'mastercard-issuer-key-1';
  const nextSalt = opts.saltSource ?? generateSalt;

  const disclosures: string[] = [];
  if (credential.email !== null) {
    disclosures.push(await createDisclosure('email', credential.email, await nextSalt()));
  }

  const payload = credential.toJSON();
  payload['_sd'] = await createSdArray(disclosures);
  payload['_sd_alg'] = 'sha-256';

  const header: IssuanceHeader = { alg: 'ES256', typ: 'sd+jwt', kid };
  return createSdJwt(header, payload, disclosures, issuerPrivateJwk);
}
