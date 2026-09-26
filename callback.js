// api/callback.js
// Función serverless de Vercel. Discord redirige aquí después de que
// el usuario autoriza (o cancela) en discord.com.
//
// Variables de entorno requeridas (configúralas en Vercel, no aquí):
//   DISCORD_CLIENT_ID
//   DISCORD_CLIENT_SECRET
//   DISCORD_REDIRECT_URI   -> debe ser IGUAL a la registrada en Discord
//   SESSION_SECRET         -> cualquier cadena larga y aleatoria, solo para firmar la cookie

const crypto = require('crypto');

module.exports = async (req, res) => {
  try {
    const { code, state, error: discordError } = req.query;
    const cookies = parseCookies(req.headers.cookie || '');

    // El usuario canceló en Discord.
    if (discordError) {
      return redirect(res, '/?error=cancelado');
    }

    // Falta el código, o el "state" no coincide con el que guardamos
    // antes de salir hacia Discord: posible CSRF o enlace manipulado.
    if (!code || !state || !cookies.oauth_state || cookies.oauth_state !== state) {
      return redirect(res, '/?error=estado_invalido');
    }

    // Intercambiamos el código por un token de acceso.
    const tokenParams = new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: process.env.DISCORD_REDIRECT_URI
    });

    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenParams
    });

    if (!tokenRes.ok) {
      console.error('Fallo al intercambiar el código', await safeText(tokenRes));
      return redirect(res, '/?error=token');
    }

    const tokenData = await tokenRes.json();

    // Con el token, pedimos los datos del usuario que autorizó.
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    if (!userRes.ok) {
      console.error('Fallo al leer el usuario', await safeText(userRes));
      return redirect(res, '/?error=usuario');
    }

    const user = await userRes.json();

    // Creamos una sesión propia (no guardamos el token de Discord).
    const session = {
      id: user.id,
      username: user.username,
      globalName: user.global_name || null,
      avatar: user.avatar,
      email: user.email || null,
      exp: Date.now() + 1000 * 60 * 60 * 12 // 12 horas
    };

    const sessionCookie = signSession(session);

    res.setHeader('Set-Cookie', [
      `staff_session=${sessionCookie}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`,
      'oauth_state=; Path=/; Max-Age=0'
    ]);

    return redirect(res, '/dashboard.html');
  } catch (err) {
    console.error('Error inesperado en /api/callback', err);
    return redirect(res, '/?error=servidor');
  }
};

function signSession(session) {
  const payload = Buffer.from(JSON.stringify(session)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
}

function parseCookies(header) {
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      out[key] = decodeURIComponent(val);
    }
  });
  return out;
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

async function safeText(response) {
  try {
    return await response.text();
  } catch {
    return '(sin cuerpo)';
  }
}
