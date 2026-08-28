// Protège tout le domaine par mot de passe, SAUF le CV et l'accueil.
// Principe : privé par défaut — une nouvelle fiche de prépa est protégée
// sans rien avoir à configurer. Seuls les fichiers listés ci-dessous sont publics.
export const config = {
  matcher: [
    '/((?!$|index\\.html|product-owner-cheffe-de-projet-digital\\.html|cv-marine-trehorel\\.html|cv-marine-trehorel\\.pdf|cheffe-de-projet-digital-ats\\.html|favicon\\.svg|Portrait-MARINE\\.jpg|robots\\.txt).*)',
  ],
};

export default function middleware(request) {
  const expected = process.env.PREP_PASSWORD;

  if (!expected) {
    return new Response('Protection non configurée (PREP_PASSWORD manquant).', {
      status: 503,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }

  const header = request.headers.get('authorization') || '';
  const [scheme, encoded] = header.split(' ');

  if (scheme === 'Basic' && encoded) {
    let password = '';
    try {
      password = atob(encoded).split(':').slice(1).join(':');
    } catch {
      password = '';
    }
    if (timingSafeEqual(password, expected)) {
      return;
    }
  }

  return new Response('Accès restreint.', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Preparation", charset="UTF-8"',
      'content-type': 'text/plain; charset=utf-8',
    },
  });
}

function timingSafeEqual(a, b) {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  let diff = bufA.length ^ bufB.length;
  for (let i = 0; i < Math.max(bufA.length, bufB.length); i++) {
    diff |= (bufA[i] ?? 0) ^ (bufB[i] ?? 0);
  }
  return diff === 0;
}
