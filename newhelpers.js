import fs from 'fs';
import crypto from 'crypto';
import { DateTime } from 'luxon';

const GRAPH = 'https://graph.facebook.com/v21.0';
const WABA_TOKEN = process.env.WABATOKEN;
const PHONE_ID = process.env.PHONEID;
const TZ = process.env.TZ || 'America/Bogota';

// Private Key loader
function loadPrivateKey() {
  const path = process.env.FLOWPRIVATEKEYPATH;
  if (!path) throw new Error('FLOWPRIVATEKEYPATH not set');
  const pass = process.env.FLOWPRIVATEKEYPASSPHRASE;
  const key = fs.readFileSync(path, 'utf8');
  return { key, passphrase: pass || undefined };
}

// Flow decrypt
export async function unwrapFlowRequest(body) {
  const encryptedFlowData = body.encryptedFlowData || body.data?.encryptedFlowData;
  const encryptedAesKey = body.encryptedAesKey || body.data?.encryptedAesKey;
  const initialVector = body.initialVector || body.data?.initialVector;

  if (!encryptedFlowData || !encryptedAesKey || !initialVector) {
    throw new Error('Missing encrypted fields');
  }

  const encKey = Buffer.from(encryptedAesKey, 'base64');
  const encData = Buffer.from(encryptedFlowData, 'base64');
  const ivReq = Buffer.from(initialVector, 'base64').slice(0, 16);

  const { key, passphrase } = loadPrivateKey();

  // RSA-OAEP-SHA256 to recover AES-128
  const aesKey = crypto.privateDecrypt(
    { key, passphrase, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    encKey
  );

  // AES-GCM with 16-byte auth tag at end of ciphertext
  const tag = encData.subarray(encData.length - 16);
  const ciphertext = encData.subarray(0, encData.length - 16);
  const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, ivReq);
  decipher.setAuthTag(tag);
  const clear = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const payload = JSON.parse(clear.toString('utf8'));

  return { payload, aesKey, iv: ivReq };
}

// Flow encrypt response - reuse same AES key, invert IV bits
export async function wrapFlowResponse(obj, aesKey, ivFromRequest) {
  const respBytes = Buffer.from(JSON.stringify(obj), 'utf8');
  const ivResp = Buffer.from(ivFromRequest.map((b) => b ^ 0xff));
  const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, ivResp);
  const enc = Buffer.concat([cipher.update(respBytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  const encPlusTag = Buffer.concat([enc, tag]);

  return {
    encryptedFlowData: encPlusTag.toString('base64'),
    initialVector: ivResp.toString('base64'),
  };
}

// Simple WA helpers
export async function waPOST(path, body) {
  const url = `${GRAPH}/${PHONE_ID}${path}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${WABA_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const t = await r.text();
    console.error('waPOST error:', r.status, t);
  }
  return r;
}

export async function sendText(to, text) {
  return waPOST('/messages', {
    messaging_product: 'whatsapp',
    to,
    type: 'text',
    text: { body: text },
  });
}

export async function sendMenu(to) {
  return waPOST('/messages', {
    messaging_product: 'whatsapp',
    to,
    type: 'interactive',
    interactive: {
      type: 'list',
      body: {
        text: 'Hola, estás escribiendo a Camila Cadena F. Fotografía. Selecciona una opción del Menú Principal',
      },
      action: {
        button: 'Ver opciones',
        sections: [
          {
            title: 'Menú Principal',
            rows: [
              { id: 'MENU1_PORTAFOLIO', title: '1. Ver tu portafolio' },
              { id: 'MENU2_AGENDAR', title: '2. Agendar una sesión' },
              { id: 'MENU3_CONTACTO', title: '3. Contacto directo' },
              { id: 'MENU4_INFO', title: '4. Otra información' },
            ],
          },
        ],
      },
    },
  });
}

export async function sendCatalog(to) {
  const catalogId = process.env.CATALOGID;
  if (!catalogId) return sendText(to, 'Portafolio no disponible por el momento.');
  return waPOST('/messages', {
    messaging_product: 'whatsapp',
    to,
    type: 'interactive',
    interactive: {
      type: 'product_list',
      header: { type: 'text', text: 'Portafolio' },
      body: { text: 'Explora el portafolio y luego elige cómo continuar.' },
      action: { catalogId, sections: [{ title: 'Galerías', productItems: [] }] },
    },
  });
}

export async function sendFlowTemplate(to) {
  const template = process.env.FLOWTEMPLATENAME || 'agendar-sesion-con-flow';
  const flowId = process.env.FLOWID;
  return waPOST('/messages', {
    messaging_product: 'whatsapp',
    to,
    type: 'template',
    template: {
      name: template,
      language: { code: 'es' },
      components: [
        {
          type: 'button',
          subtype: 'flow',
          index: 0,
          parameters: { type: 'action', action: { flowId, mode: 'published' } },
        },
      ],
    },
  });
}

export async function getBusinessHours() {
  const url = `${GRAPH}/${PHONE_ID}/whatsapp_business_profile?fields=business_hours,timezone`;
  const r = await fetch(url, { headers: { 'Authorization': `Bearer ${WABA_TOKEN}` } });
  const js = await r.json();
  return js;
}

export function fmt(dtOrISO, f) {
  const dt = typeof dtOrISO === 'string' ? DateTime.fromISO(dtOrISO) : dtOrISO;
  return dt.setZone(TZ).toFormat(f);
}

export async function computeSlots({ date, type, durationMinutes, businessHours }) {
  const duration = type === 'A' ? 45 : type === 'B' ? 60 : 90;
  const tz = businessHours?.timezone || TZ;
  const day = DateTime.fromISO(date, { zone: tz });
  const start = day.set({ hour: 9, minute: 0, second: 0, millisecond: 0 });
  const end = day.set({ hour: 18, minute: 0, second: 0, millisecond: 0 });
  const out = [];
  let cursor = start;
  while (cursor.plus({ minutes: duration }) <= end) {
    out.push(cursor);
    cursor = cursor.plus({ minutes: 30 });
  }
  return out;
}
