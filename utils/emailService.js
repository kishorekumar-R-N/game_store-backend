import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || (SMTP_USER ? SMTP_USER : 'no-reply@example.com');

let transporter = null;
let isConfigured = false;

if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
  try {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT),
      secure: Number(SMTP_PORT) === 465, // true for 465, false for other ports
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS
      },
      connectionTimeout: 10000, // 10 seconds
      debug: true, // Enable debugging logs
      logger: true // Enable detailed logs
    });

    // Mark transporter as available immediately; verification runs asynchronously.
    isConfigured = true;

    // Verify transporter in background and log result. Do not block sending attempts on verify.
    transporter.verify((err, success) => {
      if (err) {
        console.warn('SMTP transporter verification failed:', err.message || err);
      } else {
        console.log('SMTP transporter verified and ready to send emails');
      }
    });
  } catch (err) {
    console.warn('Failed to create SMTP transporter:', err && err.message ? err.message : err);
    transporter = null;
    isConfigured = false;
  }
} else {
  console.log('SMTP settings not fully configured. Email sending is disabled.');
  if (!SMTP_HOST) console.warn('Missing SMTP_HOST');
  if (!SMTP_PORT) console.warn('Missing SMTP_PORT');
  if (!SMTP_USER) console.warn('Missing SMTP_USER');
  if (!SMTP_PASS) console.warn('Missing SMTP_PASS');
}

/**
 * Send an email. If SMTP is not configured this will throw an error.
 * @param {string} to
 * @param {string} subject
 * @param {string} html
 */
export async function sendEmail(to, subject, html) {
  if (!transporter) {
    throw new Error('SMTP transporter not available');
  }

  const mailOptions = {
    from: EMAIL_FROM,
    to,
    subject,
    html
  };

  return transporter.sendMail(mailOptions);
}

export function smtpIsConfigured() {
  return isConfigured && transporter;
}
