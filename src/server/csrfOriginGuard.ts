export interface OwnerCookieMutationRequest {
  method: string;
  cookieHeader?: string;
  originHeader?: string;
  fetchSiteHeader?: string;
  configuredAppUrl?: string;
  nodeEnv?: string;
  requestProtocol?: string;
  requestHost?: string;
}

export interface OwnerCookieMutationDecision {
  allowed: boolean;
  reason?: 'SAFE_METHOD' | 'NO_OWNER_COOKIE' | 'MISSING_ORIGIN' | 'INVALID_ORIGIN' | 'APP_ORIGIN_NOT_CONFIGURED' | 'ORIGIN_MISMATCH' | 'CROSS_SITE_FETCH';
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const OWNER_COOKIE_PATTERN = /(?:^|;\s*)fv_owner_token=[^;]*/i;

/** CSRF boundary for ambient owner-session cookies. Production requires APP_URL. */
export function evaluateOwnerCookieMutationOrigin(input: OwnerCookieMutationRequest): OwnerCookieMutationDecision {
  const method = (input.method || 'GET').toUpperCase();
  if (SAFE_METHODS.has(method)) return { allowed: true, reason: 'SAFE_METHOD' };
  if (!OWNER_COOKIE_PATTERN.test(input.cookieHeader || '')) return { allowed: true, reason: 'NO_OWNER_COOKIE' };
  if ((input.fetchSiteHeader || '').toLowerCase() === 'cross-site') {
    return { allowed: false, reason: 'CROSS_SITE_FETCH' };
  }

  const originValue = (input.originHeader || '').trim();
  if (!originValue || originValue === 'null') return { allowed: false, reason: 'MISSING_ORIGIN' };

  let requestOrigin: string;
  try {
    const parsedOrigin = new URL(originValue);
    if (parsedOrigin.username || parsedOrigin.password || !['http:', 'https:'].includes(parsedOrigin.protocol)) {
      return { allowed: false, reason: 'INVALID_ORIGIN' };
    }
    requestOrigin = parsedOrigin.origin;
  } catch {
    return { allowed: false, reason: 'INVALID_ORIGIN' };
  }

  let expectedOrigin: string;
  const configuredUrl = (input.configuredAppUrl || '').trim();
  if (configuredUrl && configuredUrl !== 'MY_APP_URL') {
    try {
      const parsedAppUrl = new URL(configuredUrl);
      if (parsedAppUrl.username || parsedAppUrl.password || !['http:', 'https:'].includes(parsedAppUrl.protocol)) {
        return { allowed: false, reason: 'APP_ORIGIN_NOT_CONFIGURED' };
      }
      expectedOrigin = parsedAppUrl.origin;
    } catch {
      return { allowed: false, reason: 'APP_ORIGIN_NOT_CONFIGURED' };
    }
  } else if ((input.nodeEnv || '').toLowerCase() === 'production') {
    return { allowed: false, reason: 'APP_ORIGIN_NOT_CONFIGURED' };
  } else {
    const protocol = (input.requestProtocol || 'http').replace(/:$/, '').toLowerCase();
    const host = (input.requestHost || '').trim();
    if (!host || /[\r\n\s]/.test(host) || !['http', 'https'].includes(protocol)) {
      return { allowed: false, reason: 'APP_ORIGIN_NOT_CONFIGURED' };
    }
    expectedOrigin = `${protocol}://${host}`;
  }

  if (requestOrigin !== expectedOrigin) return { allowed: false, reason: 'ORIGIN_MISMATCH' };
  return { allowed: true };
}
