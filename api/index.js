// Servidor del Rol de Turnos – C.S. Chincha Baja (Vercel + Upstash Redis, sin dependencias)
const crypto = require('crypto');
const SECRET = process.env.SECRET || 'cambiar-esta-clave';
const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOK_ = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const R = async (...c) => { const r = await fetch(URL_, { method: 'POST', headers: { Authorization: 'Bearer ' + TOK_ }, body: JSON.stringify(c) }); return (await r.json()).result; };
const get = async (k, d) => { const v = await R('GET', k); return v ? JSON.parse(v) : d; };
const set = (k, v) => R('SET', k, JSON.stringify(v));
const slug = n => n.toLowerCase().normalize('NFD').replace(/[^a-z0-9]/g, '');
const DEF = { meta: 150, domingo: true,
  servicios: ['Medicina','Enfermería','Dental','M. Veterinario','Obstetricia','Psicología','Nutrición','Tópico','Farmacia','Estadística','SIS','Admisión','Servicios','Laboratorio','Chofer'].map(n => ({ id: slug(n), n })),
  turnos: { M:{n:'Mañana 8am–2pm',h:6,c:'#d97706'}, T:{n:'Tarde 2pm–8pm',h:6,c:'#2563eb'}, MT:{n:'Mañana y tarde 8am–8pm',h:12,c:'#7c3aed'}, GD:{n:'Guardia 8am–8pm',h:12,c:'#dc2626'}, ADM:{n:'Administrativo 8am–4:45pm',h:8.75,c:'#0f766e'}, D:{n:'Descanso (post-guardia)',h:0,c:'#64748b'}, L:{n:'Libre',h:0,c:'#94a3b8'}, V:{n:'Vacaciones / Licencia',h:0,c:'#16a34a'} } };
const hash = p => crypto.createHash('sha256').update(p + SECRET).digest('hex');
const sign = o => { const b = Buffer.from(JSON.stringify({ ...o, exp: Date.now() + 30 * 864e5 })).toString('base64url'); return b + '.' + crypto.createHmac('sha256', SECRET).update(b).digest('base64url'); };
const auth = req => { try { const [b, s] = String(req.headers['x-token'] || '').split('.'); if (s !== crypto.createHmac('sha256', SECRET).update(b).digest('base64url')) return null; const o = JSON.parse(Buffer.from(b, 'base64url')); return o.exp > Date.now() ? o : null; } catch { return null; } };
const E = m => { throw new Error(m); };
const mesOk = m => /^\d{4}-(0[1-9]|1[0-2])$/.test(m) ? m : E('Mes inválido');
const dim = m => new Date(+m.slice(0, 4), +m.slice(5), 0).getDate();
const dow = (m, d) => new Date(+m.slice(0, 4), +m.slice(5) - 1, d).getDay();
async function ctx(u) {
  if (!u) { const e = new Error('Sesión vencida. Ingrese de nuevo.'); e.auth = 1; throw e; }
  const cfg = { ...DEF, ...(await get('cfg', {})) }, staff = await get('staff', {});
  const me = u.r === 'admin' ? { dni: 'admin', nombre: 'Administrador', cargo: 'admin' } : staff[u.dni];
  if (!me || me.activo === false) { const e = new Error('Sesión vencida. Ingrese de nuevo.'); e.auth = 1; throw e; }
  return { cfg, staff, me };
}
const full = me => me.cargo === 'admin' || me.cargo === 'jefa';
const canEdit = (me, p, pub) => full(me) || (!pub && (p.dni === me.dni || (me.cargo === 'jefe' && p.servicio === me.servicio)));
const total = (cfg, d) => Math.round(Object.values(d || {}).reduce((a, c) => a + (cfg.turnos[c]?.h || 0), 0) * 100) / 100;
const H = {
  async login(b) {
    if (b.admin) { if (!process.env.ADMIN_PASSWORD || b.password !== process.env.ADMIN_PASSWORD) E('Contraseña incorrecta'); return { token: sign({ r: 'admin' }) }; }
    const dni = String(b.dni || ''); if (!/^\d{8}$/.test(dni)) E('El DNI debe tener 8 números');
    const staff = await get('staff', {}), p = staff[dni];
    if (!p) { const cfg = { ...DEF, ...(await get('cfg', {})) }; return { nuevo: true, servicios: cfg.servicios }; }
    if (p.activo === false) E('Esta persona está desactivada');
    if (p.cargo === 'jefe' || p.cargo === 'jefa') {
      if (!p.pin) E('Pida al administrador que le asigne su clave.');
      if (!b.pin) return { needPin: true };
      if (hash(String(b.pin)) !== p.pin) E('Clave incorrecta');
    }
    return { token: sign({ dni }) };
  },
  async register(b) {
    const dni = String(b.dni || ''); if (!/^\d{8}$/.test(dni)) E('DNI inválido');
    const nombre = String(b.nombre || '').trim().toUpperCase().slice(0, 80); if (nombre.length < 5) E('Escriba apellidos y nombres');
    const cfg = { ...DEF, ...(await get('cfg', {})) }; if (!cfg.servicios.some(s => s.id === b.servicio)) E('Servicio inválido');
    const staff = await get('staff', {}); if (staff[dni]) E('Ese DNI ya está registrado');
    staff[dni] = { dni, nombre, servicio: b.servicio, tipo: b.tipo === 'adm' ? 'adm' : 'turnos', cargo: 'trab', activo: true };
    await set('staff', staff); return { token: sign({ dni }) };
  },
  async state(b, u) {
    const { cfg, staff, me } = await ctx(u), mes = mesOk(b.mes);
    const rol = await get('rol:' + mes, {}), est = await get('est:' + mes, {}), pub = await get('pub:' + mes, false);
    const vis = Object.fromEntries(Object.entries(rol).filter(([dni]) => pub || full(me) || dni === me.dni || (me.cargo === 'jefe' && staff[dni]?.servicio === me.servicio)));
    const keep = p => pub || full(me) || p.dni === me.dni || (me.cargo === 'jefe' && p.servicio === me.servicio);
    const st = Object.fromEntries(Object.values(staff).filter(keep).map(p => [p.dni, { dni: p.dni, nombre: p.nombre, servicio: p.servicio, tipo: p.tipo, cargo: p.cargo, activo: p.activo !== false, pin: !!p.pin }]));
    return { cfg, staff: st, rol: vis, est, pub, me: st[me.dni] || me };
  },
  async setday(b, u) {
    const { cfg, staff, me } = await ctx(u), mes = mesOk(b.mes), p = staff[b.dni] || E('Persona no encontrada');
    const pub = await get('pub:' + mes, false); if (!canEdit(me, p, pub)) E(pub ? 'El rol ya fue aprobado.' : 'No tiene permiso para modificar este rol.');
    const d = +b.d, n = dim(mes); if (!(d >= 1 && d <= n)) E('Día inválido');
    const code = String(b.code || ''), w = dow(mes, d);
    if (code) {
      if (!cfg.turnos[code] || code === 'D') E('Turno inválido');
      if (cfg.domingo && w === 0) E('Los domingos no se trabaja');
      if (p.tipo === 'adm' ? !(['L', 'V'].includes(code) || (code === 'ADM' && w >= 1 && w <= 5)) : !['M', 'T', 'MT', 'GD', 'L', 'V'].includes(code)) E('Ese turno no corresponde a este horario');
    }
    const rol = await get('rol:' + mes, {}), r = rol[p.dni] || { d: {}, listo: false }, o = r.d, old = o[d];
    if (old === 'GD' && code !== 'GD' && o[d + 1] === 'D') delete o[d + 1];
    if (code) o[d] = code; else delete o[d];
    if (code === 'GD' && d < n && !o[d + 1]) o[d + 1] = 'D';
    if (r.listo && total(cfg, o) !== cfg.meta) r.listo = false;
    rol[p.dni] = { ...r, dni: p.dni, d: o }; await set('rol:' + mes, rol); return { ok: 1 };
  },
  async listo(b, u) {
    const { cfg, staff, me } = await ctx(u), mes = mesOk(b.mes), p = staff[b.dni] || E('Persona no encontrada');
    const pub = await get('pub:' + mes, false); if (!canEdit(me, p, pub)) E('No tiene permiso.');
    const rol = await get('rol:' + mes, {}), r = rol[p.dni] || { d: {} };
    if (b.v && total(cfg, r.d) !== cfg.meta) E('Debe completar exactamente ' + cfg.meta + ' horas.');
    rol[p.dni] = { ...r, dni: p.dni, listo: !!b.v }; await set('rol:' + mes, rol); return { ok: 1 };
  },
  async est(b, u) {
    const { me } = await ctx(u), mes = mesOk(b.mes);
    if (!(full(me) || (me.cargo === 'jefe' && me.servicio === b.sv))) E('No tiene permiso.');
    const est = await get('est:' + mes, {}); est[b.sv] = { estado: b.e === 'listo' ? 'listo' : 'borrador' }; await set('est:' + mes, est); return { ok: 1 };
  },
  async pub(b, u) {
    const { cfg, staff, me } = await ctx(u), mes = mesOk(b.mes); if (!full(me)) E('Solo la Jefa de Personal puede aprobar.');
    if (b.v) { const est = await get('est:' + mes, {}); const pend = cfg.servicios.filter(s => Object.values(staff).some(p => p.servicio === s.id && p.activo !== false) && est[s.id]?.estado !== 'listo'); if (pend.length) E('Faltan servicios por enviar: ' + pend.map(s => s.n).join(', ')); }
    await set('pub:' + mes, !!b.v); return { ok: 1 };
  },
  async cfg(b, u) {
    const { me } = await ctx(u); if (me.cargo !== 'admin') E('Solo el administrador.');
    const c = b.cfg || {}, cfg = { meta: +c.meta > 0 ? +c.meta : 150, domingo: !!c.domingo, servicios: (c.servicios || []).filter(s => s.id && String(s.n).trim()).map(s => ({ id: String(s.id).slice(0, 40), n: String(s.n).slice(0, 40) })), turnos: {} };
    for (const k of Object.keys(DEF.turnos)) cfg.turnos[k] = { ...DEF.turnos[k], n: String(c.turnos?.[k]?.n || DEF.turnos[k].n).slice(0, 50), h: Math.max(0, +c.turnos?.[k]?.h || 0) };
    await set('cfg', cfg); return { ok: 1 };
  },
  async staffset(b, u) {
    const { me } = await ctx(u); if (me.cargo !== 'admin') E('Solo el administrador.');
    const staff = await get('staff', {}), p = staff[b.dni] || E('Persona no encontrada');
    if (b.servicio) p.servicio = b.servicio; if (b.tipo) p.tipo = b.tipo === 'adm' ? 'adm' : 'turnos';
    if (b.pin) { if (!/^\d{4,8}$/.test(String(b.pin))) E('La clave debe tener de 4 a 8 números'); p.pin = hash(String(b.pin)); }
    if (b.cargo) { if (['jefe', 'jefa'].includes(b.cargo) && !p.pin) E('Primero asigne una clave (4 a 8 números) a esta persona.'); p.cargo = ['jefe', 'jefa'].includes(b.cargo) ? b.cargo : 'trab'; }
    await set('staff', staff); return { ok: 1 };
  },
  async staffadd(b, u) {
    const { cfg, me } = await ctx(u); if (me.cargo !== 'admin') E('Solo el administrador.');
    const dni = String(b.dni || ''); if (!/^\d{8}$/.test(dni)) E('El DNI debe tener 8 números');
    const nombre = String(b.nombre || '').trim().toUpperCase().slice(0, 80); if (nombre.length < 5) E('Escriba apellidos y nombres');
    if (!cfg.servicios.some(s => s.id === b.servicio)) E('Elija un servicio');
    const staff = await get('staff', {}); if (staff[dni]) E('Ese DNI ya está registrado');
    const cargo = ['jefe', 'jefa'].includes(b.cargo) ? b.cargo : 'trab', p = { dni, nombre, servicio: b.servicio, tipo: b.tipo === 'adm' ? 'adm' : 'turnos', cargo, activo: true };
    if (cargo !== 'trab') { if (!/^\d{4,8}$/.test(String(b.pin || ''))) E('Asigne una clave de 4 a 8 números'); p.pin = hash(String(b.pin)); }
    staff[dni] = p; await set('staff', staff); return { ok: 1 };
  },
  async staffdel(b, u) {
    const { me } = await ctx(u); if (me.cargo !== 'admin') E('Solo el administrador.');
    const staff = await get('staff', {}); delete staff[b.dni]; await set('staff', staff); return { ok: 1 };
  }
};
module.exports = async (req, res) => {
  try { const b = req.body || {}; if (!H[b.action]) E('Acción inválida'); const u = ['login', 'register'].includes(b.action) ? null : auth(req); res.status(200).json(await H[b.action](b, u)); }
  catch (e) { res.status(200).json({ error: e.message, auth: e.auth ? 1 : 0 }); }
};
