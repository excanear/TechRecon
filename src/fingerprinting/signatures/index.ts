import type { Signature } from '../signature';
import { backendSignatures } from './backend';
import { cmsSignatures } from './cms';
import { infrastructureSignatures } from './infrastructure';
import { javascriptSignatures } from './javascript';
import { serviceSignatures } from './services';

export const SIGNATURES: Signature[] = [
  ...cmsSignatures,
  ...javascriptSignatures,
  ...backendSignatures,
  ...infrastructureSignatures,
  ...serviceSignatures,
];
