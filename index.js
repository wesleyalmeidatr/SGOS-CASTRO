require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 3000);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_KEY || !JWT_SECRET) {
    console.error('Variaveis obrigatorias ausentes no .env: SUPABASE_URL, SUPABASE_KEY, JWT_SECRET');
    process.exit(1);
}

const allowedOrigins = FRONTEND_ORIGIN
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

function isAllowedLocalOrigin(origin) {
    try {
        const parsed = new URL(origin);
        return parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    } catch {
        return false;
    }
}

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes('*')) return callback(null, true);
        if (allowedOrigins.includes(origin)) return callback(null, true);
        if (isAllowedLocalOrigin(origin)) return callback(null, true);
        return callback(new Error('Origem nao permitida pelo CORS'));
    }
}));
app.use(helmet());
app.use(express.json({ limit: '30mb' }));

const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Muitas tentativas de login. Aguarde alguns minutos e tente novamente.'
    }
});

const publicClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false }
});

const adminClient = createClient(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY || SUPABASE_KEY,
    { auth: { persistSession: false, autoRefreshToken: false } }
);

function isMissingColumnError(error) {
    const msg = String(error?.message || '').toLowerCase();
    return (
        (msg.includes('column') && msg.includes('does not exist')) ||
        msg.includes('could not find') ||
        String(error?.code || '') === '42703'
    );
}

const _colCache = {};

async function resolveColumn(table, candidates) {
    const key = `${table}|${candidates[0]}`;
    if (key in _colCache) return _colCache[key];

    const { data: row } = await adminClient
        .from(table)
        .select('*')
        .limit(1)
        .maybeSingle();

    if (row) {
        const keys = Object.keys(row);
        for (const c of candidates) {
            if (keys.includes(c)) { _colCache[key] = c; return c; }
        }
        for (const c of candidates) {
            const norm = c.trim().toLowerCase();
            const found = keys.find((k) => k.trim().toLowerCase() === norm);
            if (found) { _colCache[key] = found; return found; }
        }
    }

    _colCache[key] = candidates[0];
    return candidates[0];
}

function sanitizeString(value) {
    return String(value || '').replace(/[<>]/g, '').trim();
}

function normalizeOSStatus(value, fallback = 'Aberta') {
    const raw = sanitizeString(value);
    if (!raw) return fallback;

    const normalized = raw
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase()
        .trim();

    if (normalized === 'aberta') return 'Aberta';
    if (normalized.startsWith('fech')) return 'Fechado';
    if (normalized.includes('aguardando') && normalized.includes('peca')) return 'Aguardando peças';
    if (normalized.includes('visto') && normalized.includes('entreg')) return 'Visto e Entregue';

    return raw;
}

function parsePositiveInt(value, fallback = 1) {
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return fallback;
    return Math.floor(n);
}

function clampInt(value, min, max, fallback) {
    const parsed = parsePositiveInt(value, fallback);
    return Math.min(max, Math.max(min, parsed));
}

function parseItemId(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    if (/^\d+$/.test(raw)) return Number(raw);
    return raw;
}

function normalizeFieldName(value) {
    return String(value || '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .toLowerCase();
}

function normalizeCode(value) {
    return String(value || '')
        .replace(/^=\(\s*"/, '')
        .replace(/"\s*\)$/, '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-zA-Z0-9]/g, '')
        .toUpperCase();
}

function detectInventarioCodeField(row) {
    const keys = Object.keys(row || {});
    if (!keys.length) return null;

    const preferred = keys.find((k) => normalizeFieldName(k).includes('codigo do produto'));
    if (preferred) return preferred;

    const fallback = keys.find((k) => {
        const norm = normalizeFieldName(k);
        return norm === 'codigo' || norm.endsWith(' codigo') || norm.includes('codigo ');
    });

    return fallback || null;
}

function getObjectField(obj, candidates, fallback = '') {
    for (const key of candidates) {
        if (obj?.[key] !== undefined && obj?.[key] !== null) {
            return obj[key];
        }
    }
    return fallback;
}

function parseImportedDate(value) {
    const raw = String(value || '').trim();
    if (!raw) return new Date().toISOString();

    const cleaned = raw.replace(/\s*\([^)]*\)\s*$/, '').trim();
    const parsed = new Date(cleaned);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();

    const br = cleaned.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$/);
    if (br) {
        const day = Number(br[1]);
        const month = Number(br[2]);
        const year = Number(br[3]);
        const hour = Number(br[4] || 0);
        const minute = Number(br[5] || 0);
        const second = Number(br[6] || 0);

        const dt = new Date(year, month - 1, day, hour, minute, second);
        if (!Number.isNaN(dt.getTime())) return dt.toISOString();
    }

    return new Date().toISOString();
}

function normalizeItemKeyValue(value) {
    return String(value || '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .toUpperCase();
}

function normalizeDateForItemKey(value) {
    const parsed = new Date(String(value || '').replace(/\s*\([^)]*\)\s*$/, '').trim());
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
    return normalizeItemKeyValue(value);
}

function buildOSItemKey(item) {
    const dateVal = normalizeDateForItemKey(getObjectField(item, ['Data', 'data']));
    const quantidadeVal = normalizeItemKeyValue(getObjectField(item, ['Quantidade', 'quantidade']));
    const codigoVal = normalizeItemKeyValue(getObjectField(item, ['Código', 'Codigo', 'codigo']));
    const descricaoVal = normalizeItemKeyValue(getObjectField(item, ['Descrição', 'Descricao', 'descricao']));
    const localidadeVal = normalizeItemKeyValue(getObjectField(item, ['Localidade', 'localidade']));
    const statusVal = normalizeItemKeyValue(getObjectField(item, ['Status', 'status']));
    const observacaoVal = normalizeItemKeyValue(getObjectField(item, ['Observação', 'Observacao', 'observacao']));

    return [
        dateVal,
        quantidadeVal,
        codigoVal,
        descricaoVal,
        localidadeVal,
        statusVal,
        observacaoVal
    ].join('|');
}

const INVENTORY_CACHE_TTL_MS = 5 * 60 * 1000;
const inventoryCache = {
    loadedAt: 0,
    codeField: null,
    entries: [],
    exactMap: new Map(),
    loadingPromise: null
};

function invalidateInventoryCache() {
    inventoryCache.loadedAt = 0;
    inventoryCache.codeField = null;
    inventoryCache.entries = [];
    inventoryCache.exactMap = new Map();
}

async function loadInventoryCache(options = {}) {
    const forceRefresh = Boolean(options.forceRefresh);
    const isFresh = !forceRefresh
        && inventoryCache.loadedAt
        && (Date.now() - inventoryCache.loadedAt) < INVENTORY_CACHE_TTL_MS
        && inventoryCache.entries.length > 0;

    if (isFresh) return inventoryCache;
    if (inventoryCache.loadingPromise) return inventoryCache.loadingPromise;

    inventoryCache.loadingPromise = (async () => {
        // Keep chunks conservative to avoid Supabase row cap truncating pages.
        const pageSize = 500;
        let offset = 0;
        let codeField = null;
        const rows = [];

        while (true) {
            const { data, error } = await adminClient
                .from('inventario')
                .select('*')
                .range(offset, offset + pageSize - 1);

            if (error) throw error;
            if (!data || data.length === 0) break;

            rows.push(...data);

            if (!codeField) {
                codeField = detectInventarioCodeField(data[0]);
            }

            if (data.length < pageSize) break;
            offset += pageSize;
        }

        const field = codeField || ' Código do produto';
        const exactMap = new Map();
        const entries = [];

        for (const row of rows) {
            const normalizedCode = normalizeCode(row?.[field]);
            if (!normalizedCode) continue;

            if (!exactMap.has(normalizedCode)) {
                exactMap.set(normalizedCode, row);
            }

            entries.push({ normalizedCode, row });
        }

        inventoryCache.loadedAt = Date.now();
        inventoryCache.codeField = field;
        inventoryCache.entries = entries;
        inventoryCache.exactMap = exactMap;

        return inventoryCache;
    })();

    try {
        return await inventoryCache.loadingPromise;
    } finally {
        inventoryCache.loadingPromise = null;
    }
}

function findInventoryItem(entries, exactMap, normalizedSearch) {
    const exactMatch = exactMap.get(normalizedSearch);
    if (exactMatch) return exactMatch;

    const startsWithMatch = entries.find((entry) => entry.normalizedCode.startsWith(normalizedSearch));
    if (startsWithMatch) return startsWithMatch.row;

    const containsMatch = entries.find((entry) => entry.normalizedCode.includes(normalizedSearch));
    return containsMatch ? containsMatch.row : null;
}

async function scanInventoryByCode(normalizedSearch) {
    const pageSize = 500;
    let offset = 0;
    let codeField = null;

    while (true) {
        const { data, error } = await adminClient
            .from('inventario')
            .select('*')
            .range(offset, offset + pageSize - 1);

        if (error) throw error;
        if (!data || data.length === 0) return null;

        if (!codeField) {
            codeField = detectInventarioCodeField(data[0]);
        }

        const field = codeField || ' Código do produto';
        const exact = data.find((row) => normalizeCode(row?.[field]) === normalizedSearch);
        if (exact) return exact;

        const starts = data.find((row) => {
            const rowCode = normalizeCode(row?.[field]);
            return rowCode && rowCode.startsWith(normalizedSearch);
        });
        if (starts) return starts;

        const contains = data.find((row) => {
            const rowCode = normalizeCode(row?.[field]);
            return rowCode && rowCode.includes(normalizedSearch);
        });
        if (contains) return contains;

        if (data.length < pageSize) return null;
        offset += pageSize;
    }
}

function escapeLikeValue(value) {
    return String(value || '').replace(/[\\%_]/g, (match) => `\\${match}`);
}

function buildInventorySearchVariants(rawCode, normalizedCode) {
    const cleaned = String(rawCode || '')
        .replace(/^=\(\s*"/, '')
        .replace(/"\s*\)$/, '')
        .trim();

    const compact = cleaned.replace(/\s+/g, '');
    const normalized = normalizeCode(cleaned);

    return Array.from(new Set([
        cleaned,
        cleaned.toUpperCase(),
        compact,
        normalizedCode,
        normalized
    ].filter(Boolean)));
}

async function findInventoryItemViaDb(rawCode, normalizedCode) {
    const variants = buildInventorySearchVariants(rawCode, normalizedCode);
    if (!variants.length) return null;

    const codeField = await resolveColumn('inventario', [' Código do produto', 'Código do produto']);

    for (const variant of variants) {
        const { data, error } = await adminClient
            .from('inventario')
            .select('*')
            .eq(codeField, variant)
            .limit(1)
            .maybeSingle();

        if (error) {
            if (isMissingColumnError(error)) return null;
            throw error;
        }

        if (data) return data;
    }

    for (const variant of variants) {
        const prefixPattern = `${escapeLikeValue(variant)}%`;
        const { data, error } = await adminClient
            .from('inventario')
            .select('*')
            .ilike(codeField, prefixPattern)
            .limit(1);

        if (error) {
            if (isMissingColumnError(error)) return null;
            throw error;
        }

        if (data?.length) return data[0];
    }

    for (const variant of variants) {
        const containsPattern = `%${escapeLikeValue(variant)}%`;
        const { data, error } = await adminClient
            .from('inventario')
            .select('*')
            .ilike(codeField, containsPattern)
            .limit(1);

        if (error) {
            if (isMissingColumnError(error)) return null;
            throw error;
        }

        if (data?.length) return data[0];
    }

    return null;
}

async function getRoleFromProfiles(userId) {
    const idColumns = ['id', 'user_id', 'uuid'];

    for (const col of idColumns) {
        const { data, error } = await adminClient
            .from('profiles')
            .select('role')
            .eq(col, userId)
            .maybeSingle();

        if (!error) {
            return String(data?.role || 'user').toLowerCase();
        }

        if (isMissingColumnError(error)) {
            continue;
        }

        throw error;
    }

    return 'user';
}

async function upsertProfileRole(userId, role) {
    const idColumns = ['id', 'user_id', 'uuid'];

    for (const col of idColumns) {
        const payload = { role };
        payload[col] = userId;

        const { error } = await adminClient
            .from('profiles')
            .upsert([payload], { onConflict: col });

        if (!error) return true;
        if (isMissingColumnError(error)) continue;
        throw error;
    }

    return false;
}

function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token ausente' });

    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'Token invalido' });

    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) return res.status(403).json({ error: 'Token expirado ou invalido' });
        req.user = payload;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (String(req.user?.role || '').toLowerCase() !== 'admin') {
        return res.status(403).json({ error: 'Acesso restrito a administradores' });
    }
    next();
}

function requireElevated(req, res, next) {
    const role = String(req.user?.role || '').toLowerCase();
    if (role !== 'admin' && role !== 'gestor') {
        return res.status(403).json({ error: 'Acesso restrito' });
    }
    next();
}

app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'sgos-backend' });
});

app.post('/login', loginLimiter, async (req, res) => {
    try {
        const email = sanitizeString(req.body?.email).toLowerCase();
        const password = String(req.body?.password || '');

        if (!email || !password) {
            return res.status(400).json({ error: 'Informe e-mail e senha' });
        }

        const { data, error } = await publicClient.auth.signInWithPassword({ email, password });
        if (error || !data?.user) {
            return res.status(401).json({ error: 'Login invalido' });
        }

        const role = await getRoleFromProfiles(data.user.id);

        const token = jwt.sign(
            { id: data.user.id, email: data.user.email, role },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        return res.json({
            token,
            id: data.user.id,
            email: data.user.email,
            role
        });
    } catch (error) {
        console.error('Erro em /login:', error);
        return res.status(500).json({ error: 'Falha interna no login' });
    }
});

app.get('/me', authenticateJWT, async (req, res) => {
    try {
        const role = await getRoleFromProfiles(req.user.id);
        return res.json({
            id: req.user.id,
            email: req.user.email,
            role
        });
    } catch (error) {
        console.error('Erro em /me:', error);
        return res.status(500).json({ error: 'Falha ao validar sessao' });
    }
});

app.post('/users', authenticateJWT, requireAdmin, async (req, res) => {
    try {
        if (!SUPABASE_SERVICE_ROLE_KEY) {
            return res.status(500).json({
                error: 'Configure SUPABASE_SERVICE_ROLE_KEY no .env para criar usuarios pelo backend'
            });
        }

        const email = sanitizeString(req.body?.email).toLowerCase();
        const password = String(req.body?.password || '');
        const rawRole = String(req.body?.role || 'user').toLowerCase();
        const role = rawRole === 'admin' ? 'admin' : rawRole === 'gestor' ? 'gestor' : 'user';

        if (!email || !password) {
            return res.status(400).json({ error: 'E-mail e senha sao obrigatorios' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Senha deve ter pelo menos 8 caracteres' });
        }

        const { data, error } = await adminClient.auth.admin.createUser({
            email,
            password,
            email_confirm: true,
            user_metadata: { role }
        });

        if (error || !data?.user?.id) {
            return res.status(400).json({ error: error?.message || 'Falha ao criar usuario' });
        }

        await upsertProfileRole(data.user.id, role);

        return res.json({ ok: true, id: data.user.id, role });
    } catch (error) {
        console.error('Erro em /users:', error);
        return res.status(500).json({ error: 'Falha ao criar usuario' });
    }
});

app.get('/users', authenticateJWT, requireAdmin, async (_req, res) => {
    try {
        const { data, error } = await adminClient.auth.admin.listUsers({ perPage: 1000 });
        if (error) return res.status(500).json({ error: error.message });

        const users = (data?.users || []).map((u) => ({
            id: u.id,
            email: u.email,
            role: String(u.user_metadata?.role || 'user').toLowerCase(),
            created_at: u.created_at,
            last_sign_in_at: u.last_sign_in_at
        }));

        return res.json({ users });
    } catch (error) {
        console.error('Erro em GET /users:', error);
        return res.status(500).json({ error: 'Falha ao listar usuarios' });
    }
});

app.patch('/users/:id', authenticateJWT, requireAdmin, async (req, res) => {
    try {
        const targetId = sanitizeString(req.params.id);
        if (!targetId) return res.status(400).json({ error: 'ID invalido' });

        if (targetId === req.user.id) {
            return res.status(400).json({ error: 'Nao e possivel alterar o proprio perfil por aqui' });
        }

        const rawRole = String(req.body?.role || 'user').toLowerCase();
        const role = rawRole === 'admin' ? 'admin' : rawRole === 'gestor' ? 'gestor' : 'user';

        const { error: authError } = await adminClient.auth.admin.updateUserById(targetId, {
            user_metadata: { role }
        });
        if (authError) return res.status(500).json({ error: authError.message });

        await upsertProfileRole(targetId, role).catch(() => {});

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em PATCH /users/:id:', error);
        return res.status(500).json({ error: 'Falha ao atualizar usuario' });
    }
});

app.delete('/users/:id', authenticateJWT, requireAdmin, async (req, res) => {
    try {
        const targetId = sanitizeString(req.params.id);
        if (!targetId) return res.status(400).json({ error: 'ID invalido' });

        if (targetId === req.user.id) {
            return res.status(400).json({ error: 'Nao e possivel excluir o proprio usuario' });
        }

        const { error } = await adminClient.auth.admin.deleteUser(targetId);
        if (error) return res.status(500).json({ error: error.message });

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em DELETE /users/:id:', error);
        return res.status(500).json({ error: 'Falha ao excluir usuario' });
    }
});

app.get('/os', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const hasExplicitPagination = req.query?.page !== undefined || req.query?.limit !== undefined;

        if (!hasExplicitPagination) {
            const pageSize = 500;
            let offset = 0;
            const allOrdens = [];

            while (true) {
                const { data, error } = await adminClient
                    .from('ordens_servico')
                    .select('*')
                    .order('data_abertura', { ascending: false })
                    .range(offset, offset + pageSize - 1);

                if (error) return res.status(500).json({ error: error.message });

                const chunk = data || [];
                if (!chunk.length) break;

                allOrdens.push(...chunk);

                if (chunk.length < pageSize) break;
                offset += pageSize;
            }

            return res.json({
                ordens: allOrdens,
                page: 1,
                limit: allOrdens.length,
                hasMore: false,
                nextPage: null
            });
        }

        const page = clampInt(req.query?.page, 1, 100000, 1);
        const limit = clampInt(req.query?.limit, 1, 500, 200);
        const from = (page - 1) * limit;
        const to = from + limit - 1;

        const { data, error } = await adminClient
            .from('ordens_servico')
            .select('*')
            .order('data_abertura', { ascending: false })
            .range(from, to);

        if (error) return res.status(500).json({ error: error.message });

        const ordens = data || [];
        const hasMore = ordens.length === limit;

        return res.json({
            ordens,
            page,
            limit,
            hasMore,
            nextPage: hasMore ? page + 1 : null
        });
    } catch (error) {
        console.error('Erro em GET /os:', error);
        return res.status(500).json({ error: 'Falha ao listar ordens' });
    }
});

app.post('/os', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const numero = sanitizeString(req.body?.numero);
        const mecanico = sanitizeString(req.body?.mecanico);
        const maquina = sanitizeString(req.body?.maquina);

        if (!numero || !mecanico) {
            return res.status(400).json({ error: 'Campos obrigatorios: numero e mecanico' });
        }

        const payload = {
            numero_os: numero,
            mecanico,
            maquina,
            status_geral: normalizeOSStatus(req.body?.status, 'Aberta')
        };

        const { error } = await adminClient.from('ordens_servico').insert([payload]);
        if (error) return res.status(500).json({ error: error.message });

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em POST /os:', error);
        return res.status(500).json({ error: 'Falha ao criar OS' });
    }
});

app.patch('/os/:numero', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const numero = sanitizeString(req.params.numero);
        const payload = {};

        if (req.body?.mecanico !== undefined) payload.mecanico = sanitizeString(req.body.mecanico);
        if (req.body?.maquina !== undefined) payload.maquina = sanitizeString(req.body.maquina);
        if (req.body?.status !== undefined) payload.status_geral = normalizeOSStatus(req.body.status, 'Aberta');

        const { error } = await adminClient
            .from('ordens_servico')
            .update(payload)
            .eq('numero_os', numero);

        if (error) return res.status(500).json({ error: error.message });

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em PATCH /os/:numero:', error);
        return res.status(500).json({ error: 'Falha ao atualizar OS' });
    }
});

app.delete('/os/:numero', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const numero = sanitizeString(req.params.numero);

        const { error: errItens } = await adminClient
            .from('itens_os')
            .delete()
            .eq('Nº OS', numero);

        if (errItens) return res.status(500).json({ error: errItens.message });

        const { error: errOs } = await adminClient
            .from('ordens_servico')
            .delete()
            .eq('numero_os', numero);

        if (errOs) return res.status(500).json({ error: errOs.message });

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em DELETE /os/:numero:', error);
        return res.status(500).json({ error: 'Falha ao excluir OS' });
    }
});

app.get('/os/:numero/items', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const numero = sanitizeString(req.params.numero);

        const { data, error } = await adminClient
            .from('itens_os')
            .select('*')
            .eq('Nº OS', numero)
            .order('Data', { ascending: false });

        if (error) return res.status(500).json({ error: error.message });

        // Normalize PK — always expose as id_item regardless of actual column name
        const itens = (data || []).map((item) => ({
            ...item,
            id_item: item.id_item ?? item.id ?? null
        }));
        return res.json({ itens });
    } catch (error) {
        console.error('Erro em GET /os/:numero/items:', error);
        return res.status(500).json({ error: 'Falha ao listar itens da OS' });
    }
});

app.post('/os/:numero/items', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const numero = sanitizeString(req.params.numero);
        const codigo = sanitizeString(req.body?.codigo).toUpperCase();
        const quantidade = parsePositiveInt(req.body?.quantidade, 1);

        if (!codigo) {
            return res.status(400).json({ error: 'Codigo do item e obrigatorio' });
        }

        const payload = {
            'Nº OS': numero,
            'Data': new Date().toISOString(),
            'Codigo': codigo,
            'Descrição': sanitizeString(req.body?.descricao),
            'Quantidade': String(quantidade),
            'Localidade': sanitizeString(req.body?.localidade),
            'Status': sanitizeString(req.body?.status || 'Pedido'),
            'Observação': sanitizeString(req.body?.observacao)
        };

        // Compatibilidade de nome de coluna: Codigo vs Código
        payload['Código'] = payload.Codigo;
        delete payload.Codigo;

        const { error } = await adminClient.from('itens_os').insert([payload]);
        if (error) return res.status(500).json({ error: error.message });

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em POST /os/:numero/items:', error);
        return res.status(500).json({ error: 'Falha ao adicionar item' });
    }
});

app.patch('/os/:numero/items/:id', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const id = parseItemId(req.params.id);
        if (id === null) {
            return res.status(400).json({ error: 'ID de item invalido' });
        }

        const payload = {};
        if (req.body?.quantidade !== undefined) payload['Quantidade'] = String(parsePositiveInt(req.body.quantidade, 1));
        if (req.body?.status !== undefined) payload['Status'] = sanitizeString(req.body.status);

        const pkCol = await resolveColumn('itens_os', ['id_item', 'id']);
        const { error } = await adminClient
            .from('itens_os')
            .update(payload)
            .eq(pkCol, id);

        if (error) return res.status(500).json({ error: error.message });

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em PATCH /os/:numero/items/:id:', error);
        return res.status(500).json({ error: 'Falha ao atualizar item' });
    }
});

app.delete('/os/:numero/items/:id', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const id = parseItemId(req.params.id);
        if (id === null) {
            return res.status(400).json({ error: 'ID de item invalido' });
        }

        const pkCol = await resolveColumn('itens_os', ['id_item', 'id']);
        const { error } = await adminClient
            .from('itens_os')
            .delete()
            .eq(pkCol, id);

        if (error) return res.status(500).json({ error: error.message });

        return res.json({ ok: true });
    } catch (error) {
        console.error('Erro em DELETE /os/:numero/items/:id:', error);
        return res.status(500).json({ error: 'Falha ao excluir item' });
    }
});

app.get('/item', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const codigo = sanitizeString(req.query?.codigo || '');
        if (!codigo) {
            return res.status(400).json({ error: 'Codigo ausente' });
        }

        const normalizedSearch = normalizeCode(codigo);
        if (!normalizedSearch) {
            return res.status(400).json({ error: 'Codigo invalido' });
        }

        let foundItem = await findInventoryItemViaDb(codigo, normalizedSearch);

        if (!foundItem) {
            let cache = await loadInventoryCache();
            foundItem = findInventoryItem(cache.entries, cache.exactMap, normalizedSearch);

            if (!foundItem) {
                cache = await loadInventoryCache({ forceRefresh: true });
                foundItem = findInventoryItem(cache.entries, cache.exactMap, normalizedSearch);
            }
        }

        if (!foundItem) {
            foundItem = await scanInventoryByCode(normalizedSearch);
        }

        return res.json({ item: foundItem || null });
    } catch (error) {
        console.error('Erro em GET /item:', error);
        return res.status(500).json({ error: 'Falha ao consultar item' });
    }
});

app.post('/importar', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const itens = Array.isArray(req.body?.itens) ? req.body.itens : null;
        if (!itens || itens.length === 0) {
            return res.status(400).json({ error: 'Formato invalido: itens precisa ser um array nao vazio' });
        }

        const conflictCandidates = [' Código do produto', 'Código do produto'];

        for (const onConflict of conflictCandidates) {
            const { error } = await adminClient
                .from('inventario')
                .upsert(itens, { onConflict });

            if (!error) {
                invalidateInventoryCache();
                return res.json({ ok: true, total: itens.length });
            }

            if (isMissingColumnError(error)) {
                continue;
            }

            return res.status(500).json({ error: error.message });
        }

        return res.status(500).json({ error: 'Nao foi possivel identificar a coluna de conflito para importacao' });
    } catch (error) {
        console.error('Erro em POST /importar:', error);
        return res.status(500).json({ error: 'Falha ao importar inventario' });
    }
});

app.post('/importar/os', authenticateJWT, requireElevated, async (req, res) => {
    try {
        const ordens = Array.isArray(req.body?.ordens) ? req.body.ordens : null;
        if (!ordens || ordens.length === 0) {
            return res.status(400).json({ error: 'Formato invalido: ordens precisa ser um array nao vazio' });
        }

        const summary = {
            receivedOrdens: ordens.length,
            processedOrdens: 0,
            createdOrdens: 0,
            updatedOrdens: 0,
            insertedItems: 0,
            skippedItems: 0,
            errors: []
        };

        for (let i = 0; i < ordens.length; i++) {
            const rawOrdem = ordens[i] || {};
            const sourceFile = sanitizeString(rawOrdem.arquivo || rawOrdem.sourceFile || `arquivo_${i + 1}`);
            const numero = sanitizeString(rawOrdem.numero);
            const mecanico = sanitizeString(rawOrdem.mecanico);
            const maquina = sanitizeString(rawOrdem.maquina);
            const status = normalizeOSStatus(rawOrdem.status || rawOrdem.status_geral || 'Aberta', 'Aberta');

            if (!numero || !mecanico) {
                summary.errors.push(`${sourceFile}: numero da OS e mecanico sao obrigatorios`);
                continue;
            }

            const { data: existingOS, error: findError } = await adminClient
                .from('ordens_servico')
                .select('id_os')
                .eq('numero_os', numero)
                .limit(1)
                .maybeSingle();

            if (findError) {
                summary.errors.push(`${sourceFile}: falha ao verificar OS ${numero} (${findError.message})`);
                continue;
            }

            if (existingOS) {
                const { error: updateError } = await adminClient
                    .from('ordens_servico')
                    .update({ mecanico, maquina, status_geral: status })
                    .eq('numero_os', numero);

                if (updateError) {
                    summary.errors.push(`${sourceFile}: falha ao atualizar OS ${numero} (${updateError.message})`);
                    continue;
                }

                summary.updatedOrdens += 1;
            } else {
                const { error: insertError } = await adminClient
                    .from('ordens_servico')
                    .insert([{ numero_os: numero, mecanico, maquina, status_geral: status }]);

                if (insertError) {
                    summary.errors.push(`${sourceFile}: falha ao criar OS ${numero} (${insertError.message})`);
                    continue;
                }

                summary.createdOrdens += 1;
            }

            summary.processedOrdens += 1;

            const rawItens = Array.isArray(rawOrdem.itens) ? rawOrdem.itens : [];
            if (!rawItens.length) continue;

            const { data: existingItems, error: existingItemsError } = await adminClient
                .from('itens_os')
                .select('*')
                .eq('Nº OS', numero);

            if (existingItemsError) {
                summary.errors.push(`${sourceFile}: falha ao listar itens da OS ${numero} (${existingItemsError.message})`);
                continue;
            }

            const existingKeys = new Set();
            for (const existingItem of (existingItems || [])) {
                const existingComparable = {
                    Data: getObjectField(existingItem, ['Data', 'data']),
                    Quantidade: getObjectField(existingItem, ['Quantidade', 'quantidade']),
                    Código: getObjectField(existingItem, ['Código', 'Codigo', 'codigo']),
                    Descrição: getObjectField(existingItem, ['Descrição', 'Descricao', 'descricao']),
                    Localidade: getObjectField(existingItem, ['Localidade', 'localidade']),
                    Status: getObjectField(existingItem, ['Status', 'status']),
                    Observação: getObjectField(existingItem, ['Observação', 'Observacao', 'observacao'])
                };
                existingKeys.add(buildOSItemKey(existingComparable));
            }

            const itensToInsert = [];
            for (const rawItem of rawItens) {
                const codigo = sanitizeString(getObjectField(rawItem, ['codigo', 'Código', 'Codigo'])).toUpperCase();
                if (!codigo) {
                    summary.skippedItems += 1;
                    continue;
                }

                const payload = {
                    'Nº OS': numero,
                    'Data': parseImportedDate(getObjectField(rawItem, ['data', 'Data'])),
                    'Código': codigo,
                    'Descrição': sanitizeString(getObjectField(rawItem, ['descricao', 'Descrição', 'Descricao'])),
                    'Quantidade': String(parsePositiveInt(getObjectField(rawItem, ['quantidade', 'Quantidade'], 1), 1)),
                    'Localidade': sanitizeString(getObjectField(rawItem, ['localidade', 'Localidade'])),
                    'Status': sanitizeString(getObjectField(rawItem, ['status', 'Status'], 'Pedido')) || 'Pedido',
                    'Observação': sanitizeString(getObjectField(rawItem, ['observacao', 'Observação', 'Observacao']))
                };

                const dedupKey = buildOSItemKey(payload);
                if (existingKeys.has(dedupKey)) {
                    summary.skippedItems += 1;
                    continue;
                }

                existingKeys.add(dedupKey);
                itensToInsert.push(payload);
            }

            if (!itensToInsert.length) continue;

            const chunkSize = 500;
            for (let start = 0; start < itensToInsert.length; start += chunkSize) {
                const batch = itensToInsert.slice(start, start + chunkSize);
                const { error: insertItemsError } = await adminClient
                    .from('itens_os')
                    .insert(batch);

                if (insertItemsError) {
                    summary.errors.push(`${sourceFile}: falha ao inserir itens da OS ${numero} (${insertItemsError.message})`);
                    break;
                }

                summary.insertedItems += batch.length;
            }
        }

        return res.json({
            ok: summary.errors.length === 0,
            summary
        });
    } catch (error) {
        console.error('Erro em POST /importar/os:', error);
        return res.status(500).json({ error: 'Falha ao importar OS em lote' });
    }
});

app.use((err, _req, res, next) => {
    if (!err) return next();

    if (String(err.message || '').includes('Origem nao permitida pelo CORS')) {
        return res.status(403).json({ error: 'Origem nao permitida' });
    }

    console.error('Erro nao tratado:', err);
    return res.status(500).json({ error: 'Falha interna do servidor' });
});

app.listen(PORT, () => {
    console.log(`Backend rodando na porta ${PORT}`);
    loadInventoryCache().catch((error) => {
        console.warn('Falha ao aquecer cache do inventario:', error.message);
    });
});
