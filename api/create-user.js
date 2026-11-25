/**
 * Vercel Serverless Function · POST /api/create-user
 * ---------------------------------------------------
 * Crea un usuario de cliente en Supabase Auth.
 *
 * Requiere la variable de entorno SUPABASE_SERVICE_ROLE_KEY (clave service_role,
 * SOLO en el servidor — nunca en el navegador). Vercel cumple el requisito
 * "sin servidores propios": es una función serverless.
 *
 * Seguridad:
 *  1. Verifica el token del que llama (Authorization: Bearer <access_token>).
 *  2. Comprueba que ese email está en la tabla `admins`.
 *  3. Solo entonces crea el usuario con la clave service_role.
 */
const SUPABASE_URL = process.env.SUPABASE_URL;                    // p. ej. https://xxxx.supabase.co
const SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY;       // SOLO servidor

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).send(JSON.stringify({ error: 'Método no permitido' }));
  }
  if (!SUPABASE_URL || !SERVICE_ROLE) {
    return res.status(500).send(JSON.stringify({ error: 'Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en el entorno' }));
  }

  try {
    /* 1) Verificar al llamador */
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).send(JSON.stringify({ error: 'Falta el token de sesión' }));

    const who = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { Authorization: `Bearer ${token}`, apikey: SERVICE_ROLE }
    });
    if (!who.ok) return res.status(401).send(JSON.stringify({ error: 'Sesión no válida' }));
    const caller = await who.json();
    const callerEmail = (caller && caller.email || '').toLowerCase();

    /* 2) ¿Es administrador? */
    const adm = await fetch(
      `${SUPABASE_URL}/rest/v1/admins?email=ilike.${encodeURIComponent(callerEmail)}&select=email`,
      { headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` } }
    );
    const admList = await adm.json();
    if (!Array.isArray(admList) || admList.length === 0) {
      return res.status(403).send(JSON.stringify({ error: 'Solo un administrador puede crear usuarios' }));
    }

    /* 3) Crear el usuario de cliente */
    const { email, password } = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    if (!email || !password || password.length < 6) {
      return res.status(400).send(JSON.stringify({ error: 'Email y contraseña (mín. 6) obligatorios' }));
    }

    const create = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: SERVICE_ROLE,
        Authorization: `Bearer ${SERVICE_ROLE}`
      },
      body: JSON.stringify({ email, password, email_confirm: true })
    });
    const created = await create.json();
    if (!create.ok) {
      return res.status(create.status).send(JSON.stringify({ error: created.msg || created.message || 'No se pudo crear el usuario' }));
    }

    return res.status(200).send(JSON.stringify({ ok: true, id: created.id, email: created.email }));
  } catch (e) {
    return res.status(500).send(JSON.stringify({ error: e.message }));
  }
}
