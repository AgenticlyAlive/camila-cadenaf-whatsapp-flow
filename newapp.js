import 'dotenv/config';
import express from 'express';
import { DateTime } from 'luxon';
import {
  waPOST,
  sendText,
  sendMenu,
  sendCatalog,
  sendFlowTemplate,
  getBusinessHours,
  computeSlots,
  unwrapFlowRequest,
  wrapFlowResponse,
  fmt,
} from './newhelpers.js';

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 3000;
const VERIFYTOKEN = process.env.VERIFYTOKEN;

// Webhook Verify
app.get('/webhook', (req, res) => {
  try {
    const verifyToken = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (verifyToken && challenge && verifyToken === VERIFYTOKEN) {
      return res.status(200).send(challenge);
    }
    return res.sendStatus(403);
  } catch (e) {
    return res.sendStatus(500);
  }
});

// Webhook Receiver
app.post('/webhook', async (req, res) => {
  try {
    const entry = req.body.entry?.[0];
    const change = entry?.changes?.[0]?.value;
    const msg = change?.messages?.[0];
    if (!msg) return res.sendStatus(200);

    const from = msg.from;
    const selection = msg.interactive?.list_reply?.id || msg.interactive?.button_reply?.id;

    if (!selection) {
      await sendMenu(from);
    } else {
      switch (selection) {
        case 'MENU1_PORTAFOLIO':
          await sendCatalog(from);
          break;
        case 'MENU2_AGENDAR':
          await sendFlowTemplate(from);
          break;
        case 'MENU3_CONTACTO':
          await sendText(
            from,
            'Camila Cadena F. ha recibido tu mensaje y te contactará por este medio en las próximas 4 horas hábiles.'
          );
          break;
        case 'MENU4_INFO':
          await sendText(from, 'Horarios, dirección del estudio, cuentas y redes sociales');
          await sendMenu(from);
          break;
        default:
          await sendMenu(from);
      }
    }
    return res.sendStatus(200);
  } catch (e) {
    console.error('webhook error:', e);
    return res.sendStatus(200);
  }
});

// Flows Data Exchange
app.post('/flows/data-exchange', async (req, res) => {
  try {
    const { payload, aesKey, iv } = await unwrapFlowRequest(req.body);
    const hours = await getBusinessHours();
    const slots = await computeSlots({
      date: payload.date,
      type: payload.type,
      durationMinutes: payload.durationMinutes,
      businessHours: hours,
    });

    const next = {
      screen: 'SLOTS',
      data: {
        availableSlots: slots.map((dt) => dt.toISO()),
      },
    };

    const encrypted = await wrapFlowResponse(next, aesKey, iv);
    return res.status(200).json(encrypted);
  } catch (e) {
    console.error('flows/data-exchange error:', e);
    return res.status(200).json({
      screen: 'ERROR',
      data: { message: 'data-exchange failed' },
    });
  }
});

// Flows Complete
app.post('/flows/complete', async (req, res) => {
  try {
    const { payload, aesKey, iv } = await unwrapFlowRequest(req.body);
    const start = DateTime.fromISO(payload.startIso);
    const end = DateTime.fromISO(payload.endIso);

    // Aquí podrías crear evento de calendario
    await sendText(
      payload.waTo,
      `Reserva confirmada el ${fmt(start, 'dd-LL-yyyy')} de ${fmt(start, 'HHmm')} a ${fmt(end, 'HHmm')}.`
    );

    const completeResp = {
      screen: 'CLOSE',
      data: { ok: true },
    };

    const encrypted = await wrapFlowResponse(completeResp, aesKey, iv);
    return res.status(200).json(encrypted);
  } catch (e) {
    console.error('flows/complete error:', e);
    return res.status(200).json({
      screen: 'ERROR',
      data: { message: 'complete failed' },
    });
  }
});

// Health Check
app.get('/health', (req, res) => {
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Server ready on PORT ${PORT}`);
});
