/**
 * CRM Bridge MCP Server + Webhook Receivers — Cloudflare Worker
 *
 * Endpoints:
 *   GET  /health               — health check
 *   POST /mcp                  — MCP JSON-RPC (Claude tool calls)
 *   POST /webhooks/ghl         — GHL webhook receiver (Ed25519 verified)
 *   POST /webhooks/basecamp    — Basecamp webhook receiver (HTTPS only, no sig)
 *   POST /webhooks/clickup     — ClickUp webhook receiver (HMAC-SHA256 verified)
 *
 * Version: 1.1.0 | Updated: 2026-03-11
 */

// ── ENV VARS (set via CF dashboard or: wrangler secret put NAME) ─────────────
// SUPABASE_URL          = https://rfxyfnxswigbprrmvixu.supabase.co
// SUPABASE_SERVICE_KEY  = eyJhbGci... (service role key)
// GHL_AGENCY_PIT        = pit-bac86506-...
// GHL_CP_PIT            = pit-76a3588c-...
// GHL_BAILEY_PIT        = pit-3a5e3c83-...
// GHL_JUMPSTART_PIT     = pit-c4f3f209-...
// GHL_CP_LOCATION_ID    = VpL3sVe4Vb1ANBx9DOL6  (set in wrangler.toml vars)
// GHL_JUMPSTART_LOC_ID  = C6ALWYCMrzuUGZQWGS33  (set in wrangler.toml vars)
// INNGEST_EVENT_KEY     = inn_... (from Inngest dashboard)
// CLICKUP_WEBHOOK_SECRET = returned when ClickUp webhook is registered

// GHL Ed25519 public key (verified 2026-03-11 from marketplace.gohighlevel.com)
const GHL_SIGNING_KEY_B64 = 'MCowBQYDK2VwAyEAi2HR1srL4o18O8BRa7gVJY7G7bupbN3H9AwJrHCDiOg=';

const GHL_BASE = 'https://services.leadconnectorhq.com';

// ── CORS HEADERS ─────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// ── SIGNATURE VERIFICATION ───────────────────────────────────────────────────

/**
 * Verify GHL Ed25519 signature.
 * Header: X-GHL-Signature (base64-encoded Ed25519 signature over raw body)
 * Verified 2026-03-11: marketplace.gohighlevel.com/docs/webhook/WebhookIntegrationGuide
 */
async function verifyGHLSignature(rawBody, signatureB64) {
  try {
    const keyBytes = Uint8Array.from(atob(GHL_SIGNING_KEY_B64), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      'spki',
      keyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const sigBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
    const bodyBytes = new TextEncoder().encode(rawBody);
    return await crypto.subtle.verify('Ed25519', key, sigBytes, bodyBytes);
  } catch {
    return false;
  }
}

/**
 * Verify ClickUp HMAC-SHA256 signature.
 * Header: X-Signature (hex-encoded HMAC-SHA256 of raw body)
 * Verified 2026-03-11: developer.clickup.com/docs/webhooksignature
 */
async function verifyClickUpSignature(rawBody, signatureHex, secret) {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigBytes = new Uint8Array(signatureHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    return await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(rawBody));
  } catch {
    return false;
  }
}

// ── INNGEST EVENT SENDER ──────────────────────────────────────────────────────

/**
 * Fire an event to Inngest on Render.
 * Endpoint: POST https://inn.gs/e/{eventKey}
 * Verified 2026-03-11: inngest.com/docs/events
 */
async function sendInngestEvent(eventKey, name, data) {
  const res = await fetch(`https://inn.gs/e/${eventKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, data, ts: Date.now() })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Inngest event send failed: ${res.status} ${err}`);
  }
  return res.json();
}

// ── WEBHOOK HANDLERS ─────────────────────────────────────────────────────────

/**
 * GHL Webhook Receiver
 *
 * Registered in: GHL Marketplace App → Advanced Settings → Webhooks
 * URL: https://crm-bridge.creativepartner.workers.dev/webhooks/ghl
 *
 * Signature: Ed25519 via X-GHL-Signature header
 * Legacy: X-WH-Signature deprecated July 1, 2025 — we only check X-GHL-Signature
 *
 * GHL event types (50+ available). Key ones we process:
 *   ContactCreate, ContactUpdate, ContactDelete, ContactTagUpdate
 *   OpportunityCreate, OpportunityUpdate, OpportunityDelete, OpportunityStageUpdate
 *   AppointmentCreate, AppointmentUpdate
 *   NoteCreate, TaskCreate, TaskComplete
 *   ConversationUnreadUpdate, InboundMessage, OutboundMessage
 */
async function handleGHLWebhook(req, env) {
  const rawBody = await req.text();
  const signature = req.headers.get('X-GHL-Signature');

  // Verify signature
  if (!signature) {
    return new Response(JSON.stringify({ error: 'Missing X-GHL-Signature' }), { status: 401, headers: CORS });
  }
  const valid = await verifyGHLSignature(rawBody, signature);
  if (!valid) {
    return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 403, headers: CORS });
  }

  // Parse payload
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers: CORS });
  }

  const eventType = payload.type || 'unknown';
  const locationId = payload.locationId || payload.location?.id;

  // Map GHL event type → Inngest event name
  const eventMap = {
    'ContactCreate':          'ghl/contact.created',
    'ContactUpdate':          'ghl/contact.updated',
    'ContactDelete':          'ghl/contact.deleted',
    'ContactTagUpdate':       'ghl/contact.tags.updated',
    'OpportunityCreate':      'ghl/opportunity.created',
    'OpportunityUpdate':      'ghl/opportunity.updated',
    'OpportunityDelete':      'ghl/opportunity.deleted',
    'OpportunityStageUpdate': 'ghl/opportunity.stage.updated',
    'AppointmentCreate':      'ghl/appointment.created',
    'AppointmentUpdate':      'ghl/appointment.updated',
    'NoteCreate':             'ghl/note.created',
    'TaskCreate':             'ghl/task.created',
    'TaskComplete':           'ghl/task.completed',
    'InboundMessage':         'ghl/message.inbound',
    'OutboundMessage':        'ghl/message.outbound',
    'ConversationUnreadUpdate': 'ghl/conversation.updated',
  };

  const inngestEventName = eventMap[eventType] || `ghl/${eventType.toLowerCase()}`;

  // Fire Inngest event — return 200 immediately, processing is async
  try {
    await sendInngestEvent(env.INNGEST_EVENT_KEY, inngestEventName, {
      ...payload,
      _meta: {
        source: 'ghl-webhook',
        receivedAt: new Date().toISOString(),
        locationId,
        eventType
      }
    });
  } catch (err) {
    // Log but still return 200 — GHL retries on non-2xx, causing duplicate events
    console.error('Inngest send failed:', err.message);
  }

  return new Response(JSON.stringify({ received: true, event: inngestEventName }), { status: 200, headers: CORS });
}

/**
 * Basecamp Webhook Receiver
 *
 * Registered via: Basecamp API — POST /webhooks.json (or via OAuth app config)
 * URL: https://crm-bridge.creativepartner.workers.dev/webhooks/basecamp
 *
 * No signature verification — Basecamp relies on HTTPS only.
 * Verified 2026-03-11: github.com/basecamp/bc3-api
 *
 * Basecamp event types:
 *   Comment::Created, Comment::Updated
 *   Todo::Created, Todo::Updated, Todo::Completed, Todo::Uncompleted
 *   Message::Created, Message::Updated
 *   TodoList::Created, Document::Created, Upload::Created
 */
async function handleBasecampWebhook(req, env) {
  const rawBody = await req.text();

  // Verify it's actually from Basecamp via User-Agent check (defense in depth)
  const userAgent = req.headers.get('User-Agent') || '';
  if (!userAgent.includes('Basecamp')) {
    console.warn('Basecamp webhook: unexpected User-Agent:', userAgent);
    // Don't reject — just log. Some Basecamp deliveries may vary.
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers: CORS });
  }

  const kind = payload.kind || 'unknown';
  // kind format: "comment_created", "todo_created", etc.
  // Map to Inngest event: basecamp/comment.created, basecamp/todo.created, etc.
  const inngestEventName = `basecamp/${kind.replace(/_/g, '.')}`;

  try {
    await sendInngestEvent(env.INNGEST_EVENT_KEY, inngestEventName, {
      ...payload,
      _meta: {
        source: 'basecamp-webhook',
        receivedAt: new Date().toISOString(),
        kind
      }
    });
  } catch (err) {
    console.error('Inngest send failed:', err.message);
  }

  // Basecamp expects 2xx — must respond quickly
  return new Response(JSON.stringify({ received: true, event: inngestEventName }), { status: 200, headers: CORS });
}

/**
 * ClickUp Webhook Receiver
 *
 * Registered via: POST https://api.clickup.com/api/v2/team/{team_id}/webhook
 * URL: https://crm-bridge.creativepartner.workers.dev/webhooks/clickup
 *
 * Signature: HMAC-SHA256 via X-Signature header (hex-encoded)
 * Secret: returned in webhook creation response, stored as CLICKUP_WEBHOOK_SECRET env var
 * Verified 2026-03-11: developer.clickup.com
 *
 * ClickUp event types:
 *   taskCreated, taskUpdated, taskDeleted, taskCommentPosted, taskCommentUpdated
 *   taskStatusUpdated, taskPriorityUpdated, taskAssigneeUpdated, taskDueDateUpdated
 *   listCreated, listUpdated, listDeleted
 *   folderCreated, folderUpdated, folderDeleted
 *   spaceCreated, spaceUpdated, spaceDeleted
 *
 * CRITICAL: Webhooks silently suspend after 100 consecutive failures.
 * Monitor fail_count via GET /v2/webhook/{webhook_id}
 */
async function handleClickUpWebhook(req, env) {
  const rawBody = await req.text();
  const signature = req.headers.get('X-Signature');

  // Verify signature (required — ClickUp webhooks always include it)
  if (!signature) {
    return new Response(JSON.stringify({ error: 'Missing X-Signature' }), { status: 401, headers: CORS });
  }

  if (!env.CLICKUP_WEBHOOK_SECRET) {
    // Secret not configured yet — log and accept (for initial setup only)
    console.warn('CLICKUP_WEBHOOK_SECRET not set — skipping signature verification');
  } else {
    const valid = await verifyClickUpSignature(rawBody, signature, env.CLICKUP_WEBHOOK_SECRET);
    if (!valid) {
      return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 403, headers: CORS });
    }
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers: CORS });
  }

  const eventType = payload.event || 'unknown';
  // Map to Inngest event name: clickup/task.created, clickup/task.updated, etc.
  const inngestEventName = `clickup/${eventType.replace(/([A-Z])/g, '.$1').toLowerCase().replace(/^\./, '')}`;

  try {
    await sendInngestEvent(env.INNGEST_EVENT_KEY, inngestEventName, {
      ...payload,
      _meta: {
        source: 'clickup-webhook',
        receivedAt: new Date().toISOString(),
        eventType
      }
    });
  } catch (err) {
    console.error('Inngest send failed:', err.message);
  }

  // Must return 200 — ClickUp suspends webhook after 100 non-2xx responses
  return new Response(JSON.stringify({ received: true, event: inngestEventName }), { status: 200, headers: CORS });
}

// ── MCP TOOL DEFINITIONS ─────────────────────────────────────────────────────
const TOOLS = [
  // GHL CONTACTS
  {
    name: 'ghl_search_contacts',
    description: 'Search GHL contacts by name, email, phone, or tag',
    inputSchema: {
      type: 'object',
      properties: {
        query:       { type: 'string', description: 'Search term' },
        locationId:  { type: 'string', description: 'GHL location ID (defaults to Creative Partner)' },
        limit:       { type: 'number', description: 'Max results (default 20)' },
        tag:         { type: 'string', description: 'Filter by tag' }
      }
    }
  },
  {
    name: 'ghl_get_contact',
    description: 'Get full contact record by ID',
    inputSchema: {
      type: 'object',
      properties: {
        contactId:  { type: 'string' },
        locationId: { type: 'string' }
      },
      required: ['contactId']
    }
  },
  {
    name: 'ghl_create_contact',
    description: 'Create a new GHL contact',
    inputSchema: {
      type: 'object',
      properties: {
        locationId: { type: 'string' },
        firstName:  { type: 'string' },
        lastName:   { type: 'string' },
        email:      { type: 'string' },
        phone:      { type: 'string' },
        tags:       { type: 'array', items: { type: 'string' } },
        customFields: { type: 'object' }
      },
      required: ['firstName']
    }
  },
  {
    name: 'ghl_update_contact',
    description: 'Update an existing GHL contact',
    inputSchema: {
      type: 'object',
      properties: {
        contactId:  { type: 'string' },
        locationId: { type: 'string' },
        firstName:  { type: 'string' },
        lastName:   { type: 'string' },
        email:      { type: 'string' },
        phone:      { type: 'string' },
        tags:       { type: 'array', items: { type: 'string' } },
        customFields: { type: 'object' }
      },
      required: ['contactId']
    }
  },
  {
    name: 'ghl_add_contact_note',
    description: 'Add a note to a GHL contact',
    inputSchema: {
      type: 'object',
      properties: {
        contactId:  { type: 'string' },
        locationId: { type: 'string' },
        body:       { type: 'string' }
      },
      required: ['contactId', 'body']
    }
  },
  {
    name: 'ghl_add_contact_tags',
    description: 'Add tags to a GHL contact',
    inputSchema: {
      type: 'object',
      properties: {
        contactId:  { type: 'string' },
        locationId: { type: 'string' },
        tags:       { type: 'array', items: { type: 'string' } }
      },
      required: ['contactId', 'tags']
    }
  },
  // GHL CONVERSATIONS
  {
    name: 'ghl_get_conversations',
    description: 'Get conversations for a contact or location',
    inputSchema: {
      type: 'object',
      properties: {
        locationId:  { type: 'string' },
        contactId:   { type: 'string' },
        status:      { type: 'string', enum: ['open', 'closed', 'all'] },
        limit:       { type: 'number' }
      }
    }
  },
  {
    name: 'ghl_send_message',
    description: 'Send SMS, email, or WhatsApp message via GHL',
    inputSchema: {
      type: 'object',
      properties: {
        locationId:     { type: 'string' },
        contactId:      { type: 'string' },
        type:           { type: 'string', enum: ['SMS', 'Email', 'WhatsApp'] },
        message:        { type: 'string' },
        subject:        { type: 'string' },
        emailFrom:      { type: 'string' },
        emailTo:        { type: 'string' }
      },
      required: ['contactId', 'type', 'message']
    }
  },
  // GHL OPPORTUNITIES
  {
    name: 'ghl_search_opportunities',
    description: 'Search pipeline opportunities',
    inputSchema: {
      type: 'object',
      properties: {
        locationId:  { type: 'string' },
        query:       { type: 'string' },
        pipelineId:  { type: 'string' },
        status:      { type: 'string', enum: ['open', 'won', 'lost', 'abandoned', 'all'] },
        limit:       { type: 'number' }
      }
    }
  },
  {
    name: 'ghl_create_opportunity',
    description: 'Create a pipeline opportunity',
    inputSchema: {
      type: 'object',
      properties: {
        locationId:      { type: 'string' },
        pipelineId:      { type: 'string' },
        pipelineStageId: { type: 'string' },
        contactId:       { type: 'string' },
        name:            { type: 'string' },
        monetaryValue:   { type: 'number' },
        status:          { type: 'string' }
      },
      required: ['pipelineId', 'contactId', 'name']
    }
  },
  {
    name: 'ghl_update_opportunity',
    description: 'Update opportunity stage or status',
    inputSchema: {
      type: 'object',
      properties: {
        opportunityId:   { type: 'string' },
        locationId:      { type: 'string' },
        pipelineStageId: { type: 'string' },
        status:          { type: 'string', enum: ['open', 'won', 'lost', 'abandoned'] },
        monetaryValue:   { type: 'number' }
      },
      required: ['opportunityId']
    }
  },
  // GHL WORKFLOWS
  {
    name: 'ghl_get_workflows',
    description: 'List all GHL automation workflows',
    inputSchema: {
      type: 'object',
      properties: { locationId: { type: 'string' } }
    }
  },
  {
    name: 'ghl_add_contact_to_workflow',
    description: 'Enroll a contact in a GHL workflow',
    inputSchema: {
      type: 'object',
      properties: {
        contactId:  { type: 'string' },
        workflowId: { type: 'string' },
        locationId: { type: 'string' }
      },
      required: ['contactId', 'workflowId']
    }
  },
  // GHL CALENDARS
  {
    name: 'ghl_get_calendars',
    description: 'List all GHL calendars',
    inputSchema: {
      type: 'object',
      properties: { locationId: { type: 'string' } }
    }
  },
  {
    name: 'ghl_get_appointments',
    description: 'Get appointments for a calendar or contact',
    inputSchema: {
      type: 'object',
      properties: {
        locationId:  { type: 'string' },
        calendarId:  { type: 'string' },
        contactId:   { type: 'string' },
        startTime:   { type: 'string' },
        endTime:     { type: 'string' }
      }
    }
  },
  // BASECAMP
  {
    name: 'bc_get_projects',
    description: 'List all Basecamp projects',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'bc_get_todolists',
    description: 'Get all to-do lists in a Basecamp project',
    inputSchema: {
      type: 'object',
      properties: {
        projectId: { type: 'string' },
        todosetId: { type: 'string' }
      },
      required: ['projectId']
    }
  },
  {
    name: 'bc_get_todos',
    description: 'Get to-dos in a Basecamp to-do list',
    inputSchema: {
      type: 'object',
      properties: {
        projectId:  { type: 'string' },
        todolistId: { type: 'string' }
      },
      required: ['projectId', 'todolistId']
    }
  },
  {
    name: 'bc_create_todo',
    description: 'Create a to-do in Basecamp',
    inputSchema: {
      type: 'object',
      properties: {
        projectId:   { type: 'string' },
        todolistId:  { type: 'string' },
        content:     { type: 'string' },
        description: { type: 'string' },
        assigneeIds: { type: 'array', items: { type: 'number' } },
        dueOn:       { type: 'string', description: 'YYYY-MM-DD' }
      },
      required: ['projectId', 'todolistId', 'content']
    }
  },
  {
    name: 'bc_update_todo',
    description: 'Update a Basecamp to-do',
    inputSchema: {
      type: 'object',
      properties: {
        projectId:   { type: 'string' },
        todoId:      { type: 'string' },
        content:     { type: 'string' },
        description: { type: 'string' },
        assigneeIds: { type: 'array', items: { type: 'number' } },
        dueOn:       { type: 'string' },
        completed:   { type: 'boolean' }
      },
      required: ['projectId', 'todoId']
    }
  },
  {
    name: 'bc_create_message',
    description: 'Post a message to a Basecamp project message board',
    inputSchema: {
      type: 'object',
      properties: {
        projectId:      { type: 'string' },
        messageBoardId: { type: 'string' },
        subject:        { type: 'string' },
        content:        { type: 'string' },
        status:         { type: 'string', enum: ['active', 'draft'] }
      },
      required: ['projectId', 'subject', 'content']
    }
  },
  // N8N
  {
    name: 'n8n_execute_workflow',
    description: 'Execute an n8n workflow by webhook URL or name',
    inputSchema: {
      type: 'object',
      properties: {
        workflow_name: { type: 'string' },
        webhook_url:   { type: 'string' },
        payload:       { type: 'string', description: 'JSON payload string' }
      }
    }
  },
  {
    name: 'n8n_fire_session_enforcement',
    description: 'Fire the session enforcement webhook — logs session to Supabase + Inngest',
    inputSchema: {
      type: 'object',
      properties: {
        title:              { type: 'string' },
        rationale:          { type: 'string' },
        change_description: { type: 'string' },
        domain:             { type: 'string' },
        evolution_type:     { type: 'string' },
        lesson_learned:     { type: 'string' },
        expected_outcome:   { type: 'string' },
        actor:              { type: 'string' }
      },
      required: ['title', 'rationale', 'change_description']
    }
  }
];

// ── HELPERS ───────────────────────────────────────────────────────────────────
function getPIT(env, locationId) {
  if (!locationId || locationId === env.GHL_CP_LOCATION_ID) return env.GHL_CP_PIT;
  if (locationId === env.GHL_JUMPSTART_LOC_ID) return env.GHL_JUMPSTART_PIT;
  return env.GHL_AGENCY_PIT;
}

async function ghlRequest(env, method, path, locationId, body) {
  const token = getPIT(env, locationId);
  const res = await fetch(`${GHL_BASE}${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type':  'application/json',
      'Version':       '2021-07-28'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GHL ${method} ${path} → ${res.status}: ${err}`);
  }
  return res.json();
}

async function bcRequest(env, method, path, body) {
  const sbRes = await fetch(
    `${env.SUPABASE_URL}/rest/v1/api_credential?credential_key=eq.access_token&service=eq.basecamp&select=credential_value`,
    { headers: { apikey: env.SUPABASE_SERVICE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_KEY}` } }
  );
  const [cred] = await sbRes.json();
  const token = typeof cred.credential_value === 'string'
    ? cred.credential_value
    : cred.credential_value?.access_token || cred.credential_value?.token;

  const res = await fetch(`https://3.basecampapi.com/6162345${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type':  'application/json',
      'User-Agent':    'CreativePartnerOS (chad@creativepartnersolutions.com)'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!res.ok) throw new Error(`Basecamp ${method} ${path} → ${res.status}`);
  return method === 'DELETE' ? { ok: true } : res.json();
}

// ── TOOL EXECUTOR ─────────────────────────────────────────────────────────────
async function executeTool(name, args, env) {
  const loc = args.locationId || env.GHL_CP_LOCATION_ID;

  switch (name) {
    case 'ghl_search_contacts': {
      const params = new URLSearchParams({ locationId: loc, limit: args.limit || 20 });
      if (args.query) params.set('query', args.query);
      if (args.tag)   params.set('tags', args.tag);
      return ghlRequest(env, 'GET', `/contacts/?${params}`, loc);
    }
    case 'ghl_get_contact':
      return ghlRequest(env, 'GET', `/contacts/${args.contactId}`, loc);
    case 'ghl_create_contact':
      return ghlRequest(env, 'POST', '/contacts/', loc, { ...args, locationId: loc });
    case 'ghl_update_contact':
      return ghlRequest(env, 'PUT', `/contacts/${args.contactId}`, loc, args);
    case 'ghl_add_contact_note':
      return ghlRequest(env, 'POST', `/contacts/${args.contactId}/notes`, loc, { body: args.body, userId: '' });
    case 'ghl_add_contact_tags':
      return ghlRequest(env, 'POST', `/contacts/${args.contactId}/tags`, loc, { tags: args.tags });
    case 'ghl_get_conversations': {
      const p = new URLSearchParams({ locationId: loc });
      if (args.contactId) p.set('contactId', args.contactId);
      if (args.status && args.status !== 'all') p.set('status', args.status);
      if (args.limit) p.set('limit', args.limit);
      return ghlRequest(env, 'GET', `/conversations/?${p}`, loc);
    }
    case 'ghl_send_message':
      return ghlRequest(env, 'POST', '/conversations/messages', loc, args);
    case 'ghl_search_opportunities': {
      const p = new URLSearchParams({ location_id: loc });
      if (args.query)      p.set('q', args.query);
      if (args.pipelineId) p.set('pipeline_id', args.pipelineId);
      if (args.status && args.status !== 'all') p.set('status', args.status);
      if (args.limit)      p.set('limit', args.limit);
      return ghlRequest(env, 'GET', `/opportunities/search?${p}`, loc);
    }
    case 'ghl_create_opportunity':
      return ghlRequest(env, 'POST', '/opportunities/', loc, args);
    case 'ghl_update_opportunity':
      return ghlRequest(env, 'PUT', `/opportunities/${args.opportunityId}`, loc, args);
    case 'ghl_get_workflows':
      return ghlRequest(env, 'GET', `/workflows/?locationId=${loc}`, loc);
    case 'ghl_add_contact_to_workflow':
      return ghlRequest(env, 'POST', `/contacts/${args.contactId}/workflow/${args.workflowId}`, loc, { eventStartTime: new Date().toISOString() });
    case 'ghl_get_calendars':
      return ghlRequest(env, 'GET', `/calendars/?locationId=${loc}`, loc);
    case 'ghl_get_appointments': {
      const p = new URLSearchParams({ locationId: loc });
      if (args.calendarId) p.set('calendarId', args.calendarId);
      if (args.contactId)  p.set('contactId', args.contactId);
      if (args.startTime)  p.set('startTime', args.startTime);
      if (args.endTime)    p.set('endTime', args.endTime);
      return ghlRequest(env, 'GET', `/calendars/events?${p}`, loc);
    }
    case 'bc_get_projects':
      return bcRequest(env, 'GET', '/projects.json');
    case 'bc_get_todolists': {
      if (!args.todosetId) {
        const project = await bcRequest(env, 'GET', `/projects/${args.projectId}.json`);
        const todoset = project.dock?.find(d => d.name === 'todoset');
        if (!todoset) throw new Error('No todoset found in project');
        const ts = await bcRequest(env, 'GET', `/buckets/${args.projectId}/todosets/${todoset.id}.json`);
        return bcRequest(env, 'GET', `/buckets/${args.projectId}/todosets/${ts.id}/todolists.json`);
      }
      return bcRequest(env, 'GET', `/buckets/${args.projectId}/todosets/${args.todosetId}/todolists.json`);
    }
    case 'bc_get_todos':
      return bcRequest(env, 'GET', `/buckets/${args.projectId}/todolists/${args.todolistId}/todos.json`);
    case 'bc_create_todo':
      return bcRequest(env, 'POST', `/buckets/${args.projectId}/todolists/${args.todolistId}/todos.json`, {
        content: args.content, description: args.description,
        assignee_ids: args.assigneeIds, due_on: args.dueOn
      });
    case 'bc_update_todo':
      return bcRequest(env, 'PUT', `/buckets/${args.projectId}/todos/${args.todoId}.json`, {
        content: args.content, description: args.description,
        assignee_ids: args.assigneeIds, due_on: args.dueOn, completed: args.completed
      });
    case 'bc_create_message': {
      if (!args.messageBoardId) {
        const project = await bcRequest(env, 'GET', `/projects/${args.projectId}.json`);
        const mb = project.dock?.find(d => d.name === 'message_board');
        if (!mb) throw new Error('No message board found');
        args.messageBoardId = mb.id;
      }
      return bcRequest(env, 'POST', `/buckets/${args.projectId}/message_boards/${args.messageBoardId}/messages.json`, {
        subject: args.subject, content: args.content, status: args.status || 'active'
      });
    }
    case 'n8n_execute_workflow': {
      const KNOWN = {
        'session-enforcement':        'https://creativepartneros.app.n8n.cloud/webhook/session-enforcement',
        'dataforseo-keyword-ideas':   'https://creativepartneros.app.n8n.cloud/webhook/dataforseo-keyword-ideas',
        'dataforseo-backlink-summary':'https://creativepartneros.app.n8n.cloud/webhook/dataforseo-backlink-summary',
        'google-reviews':             'https://creativepartneros.app.n8n.cloud/webhook/google-reviews'
      };
      const url = args.webhook_url || KNOWN[args.workflow_name];
      if (!url) throw new Error(`Unknown workflow: ${args.workflow_name}`);
      const payload = args.payload ? JSON.parse(args.payload) : {};
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      return res.json();
    }
    case 'n8n_fire_session_enforcement': {
      const url = 'https://creativepartneros.app.n8n.cloud/webhook/session-enforcement';
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...args, actor: args.actor || 'claude', source: 'cf-worker' })
      });
      return res.json();
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ── MCP JSON-RPC HANDLER ──────────────────────────────────────────────────────
async function handleMCP(req, env) {
  const body = await req.json();
  const { id, method, params } = body;

  if (method === 'initialize') {
    return { jsonrpc: '2.0', id, result: {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'crm-bridge', version: '1.1.0' }
    }};
  }

  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  }

  if (method === 'tools/call') {
    const { name, arguments: args } = params;
    try {
      const result = await executeTool(name, args || {}, env);
      return {
        jsonrpc: '2.0', id,
        result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0', id,
        error: { code: -32603, message: err.message }
      };
    }
  }

  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
}

// ── MAIN FETCH HANDLER ────────────────────────────────────────────────────────
export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        version: '1.1.0',
        tools: TOOLS.length,
        webhooks: ['/webhooks/ghl', '/webhooks/basecamp', '/webhooks/clickup'],
        timestamp: new Date().toISOString()
      }), { headers: CORS });
    }

    if (url.pathname === '/mcp' && req.method === 'POST') {
      const result = await handleMCP(req, env);
      return new Response(JSON.stringify(result), { headers: CORS });
    }

    // Webhook receivers
    if (url.pathname === '/webhooks/ghl' && req.method === 'POST') {
      return handleGHLWebhook(req, env);
    }
    if (url.pathname === '/webhooks/basecamp' && req.method === 'POST') {
      return handleBasecampWebhook(req, env);
    }
    if (url.pathname === '/webhooks/clickup' && req.method === 'POST') {
      return handleClickUpWebhook(req, env);
    }

    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: CORS });
  }
};
