/// <reference types="@fastly/js-compute" />

import * as jwt from 'jsonwebtoken';

// Configuration values - modify these to change the behavior of this fiddle
const cfg = {
  // How to handle JWT verification failure - 'deny' or 'allow'
  //   deny - Redirects to /login with redirect_to query set to original request URL
  //   allow - Sets request header auth-state: anonymous and fetches through
  anonAccess: 'allow',

  // Behavior when exp claim is missing - 'block' or 'anonymous'
  timeInvalid: 'block',

  // Behavior when request path doesn't match path claim - 'block' or 'anonymous'
  pathInvalid: 'anonymous',
};

// Public key, whose private key is used to sign tokens used in the tests
// It is an RS512 public key that can be generated with openssl like
// ssh-keygen -t rsa -b 4096 -m PEM -E SHA512 -f jwtRS512.key -N ""
// openssl rsa -in jwtRS512.key -pubout -outform PEM -out jwtRS512.key.pub
// cat jwtRS512.key # private key (use this for signing, don't share this!)
// cat jwtRS512.key.pub # public key (pasted below)
const PUBLIC_KEY = `\
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsxCH4oVozTOx56a0MX8w
wIKqXP3LahmCsMYGdoimoFfaU7+820Ww2zNHuo4dJHLq+zwBOzaCxC9rtCNKiCNR
+n4Oy0zEdV+4nbSMIb1tGcIJOQCXtKrM/y+Dd0dXZdYrdLBkqI7VRHuIdSKQWIAu
jq3W58U4obXWSsTWj40PPN5tgd6yh97qP0sqqVZvmBqhxFmfmpREn0dXhUSKLsUR
3ut84fhsHI1LHyB5I+nh8OSMRuWFwm48+xaDrA2ZDvWQFX1/A9zY0amDUeEGzqbF
MyJB/9TG8OIDdHGf7QsW0W5sa6LwLtzna0yTxs5T3HcL4QBG9ro8w0nJCHGrqtA6
D1uiiK3h8iHgYISYRbVSQwjRZHYg/x7j9glf3xzpdmDzgenms1zH+o3tWiUKMj+m
dv0V71r1lN1KE7l19kLchi0+Cmf0maMqborWseOjZSI3wK9aZ0lOVQOfIrO2Y5bY
whd77Q5STV0KqXsCD11KTKcHUrzYndP/4RYfLlaskN7J9ZGAvdDZ3ZIQb4BngEOb
hpzdeiIa2cn/rfyw2K5dzgiglyGOUDDlfiY+5rbS6J2IIHibX+/N+g+cdA6oMFGV
RSNbx72cVQ0viiMAlremsrkqPIBIw1r+XM6PtR3CWDUegHtuYd+/6IQC4Q+JO4jE
NhE9JVjIx0OSclteIP2SnJ0CAwEAAQ==
-----END PUBLIC KEY-----`;

/**
 * Get JWT token value from request Cookie
 * @param req { Request }
 */
function getJwtTokenFromRequest(req) {
  const cookies = req.headers.get('Cookie');
  if (cookies == null) {
    return null;
  }

  const auth = cookies.split(';')
    .map(v =>
      v.split('=')
        .map(val => decodeURIComponent(val.trim()))
    )
    .find(([k, _]) => k === 'auth')
  if (auth == null) {
    return null;
  }

  return auth[1];
}

/**
 * Remove JWT token value from backend request Cookie
 * @param req { Request }
 */
function removeJwtTokenFromRequest(req) {
  const cookies = req.headers.get('Cookie');
  if (cookies == null) {
    // Cookie not there, no biggie
    return;
  }

  const otherCookies = cookies.split(';')
    .filter(v => decodeURIComponent(v.split('=')[0].trim()) !== 'auth');

  req.headers.set('Cookie', otherCookies.join(';'));
}

/**
 * Validate JWT token in request
 * @param req { Request }
 */
function validateJwtSignature(req) {
  const token = getJwtTokenFromRequest(req);
  if (token == null) {
    throw new Error('No JWT in request');
  }

  // If this throws, then validation has failed
  const payload = jwt.verify(token, PUBLIC_KEY);

  // jwt.verify() will already verify the "expires" and "not before" timestamps
  // against the current time.
  // This additional check will make sure that we don't pass
  // the check when the exp claim is not present in the payload.
  if (cfg.timeInvalid === 'block') {
    if (payload.exp == null) {
      throw new Error('exp claim not present');
    }
  }

  // Check path constraint
  if (cfg.pathInvalid === 'block') {
    if (payload.path != null) {
      // Convert glob to regex
      const pattern = payload.path.replace(/([.?+^$[\\(){}|\/-])/g, "\\$1").replace(/\*/g, '.*');
      const regex = new RegExp(pattern);
      if (!regex.test(new URL(req.url).pathname)) {
        throw new Error('path claim not matched');
      }
    }
  }

  return payload;
}

/**
 * Build a redirect response to /login
 * @param url { URL }
 * @param message { string | null }
 */
function buildRedirectResponse(url, message = null) {
  const location = new URL('/login', url);
  location.searchParams.set('return_to', url.pathname + url.search);

  const res = Response.redirect(location.pathname + location.search, 307);
  if (message != null) {
    res.headers.set('fastly-jwt-error', message);
  }

  return res;
}

async function handleRequest(event) {

  // Modify request for backend
  const req = event.request.clone();

  let requiredTag = undefined;
  try {
    console.log('Checking JWT...');

    const payload = validateJwtSignature(event.request);

    // We passed all the verification
    console.log('JWT Token verified successfully!');

    req.headers.set('auth-state', 'authenticated');
    req.headers.set('auth-userid', payload.uid ?? '');
    req.headers.set('auth-groups', payload.groups ?? '');
    req.headers.set('auth-name', payload.name ?? '');
    req.headers.set('auth-is-admin', payload.admin ? '1' : '0');
    requiredTag = payload.tag;

    // If the token was valid, we don't want to pass it through to backend
    removeJwtTokenFromRequest(req);
  } catch(ex) {
    if (cfg.anonAccess === 'deny') {
      console.log(`Response redirect, ${ex.message}`);
      return buildRedirectResponse(new URL(event.request.url), ex.message);
    }

    console.log(`Allow anonymous access, ${ex.message}`);
    req.headers.set('auth-state', 'anonymous');
  }

  // Perform fetch
  const resp = await fetch(req, { 'backend': 'origin_0', });

  // Check Tag availability in response
  if (requiredTag != null) {
    if (
      !(
        resp.headers.get('surrogate-key') ?? '')
          .split(/\s+/)
          .some(v => v === requiredTag
      )
    ) {
      return buildRedirectResponse(new URL(event.request.url), 'Required tag missing');
    }
  }

  return resp;
}

addEventListener("fetch", (event) => event.respondWith(handleRequest(event)));
