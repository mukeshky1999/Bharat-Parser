/**
 * Indian Law Enforcement Agency (LEA) Pre-compiled Regex Catalog.
 * High-precision extractors for UPI, TRAI DLT SMS headers, Banking, and Crypto identifiers.
 */

export const INDIAN_LEA_REGEX = {
  // 12-Digit NPCI UTR / RRN (Unique Transaction Reference)
  UTR_12_DIGIT: /\b([0-9]{12})\b/g,

  // UPI Virtual Payment Address (VPA) / Handles
  UPI_VPA_SPECIFIC: /[a-zA-Z0-9.\-_]{2,256}@(okaxis|okhdfcbank|okicici|oksbi|ybl|axl|ibl|paytm|apl|upi|barodampay|federal|postbank|jupiteraxis|fbl|idfcbank|axisbank|icici|kotak|sbi|aubank|indus)/gi,
  UPI_VPA_GENERIC: /[a-zA-Z0-9.\-_]{2,128}@[a-zA-Z]{2,32}/g,

  // TRAI DLT 6-character Alpha Header (e.g., "AD-HDFCBK", "VK-SBIINB", "JM-PAYTM", "CP-ICICIB")
  TRAI_DLT_SENDER: /^[A-Za-z]{2}-([A-Za-z0-9]{6})$/,

  // Indian Bank Account Mask Patterns (e.g., "A/c *4921", "Account ending in XX3829")
  BANK_ACCOUNT_MASK: /(?:A\/c\s*(?:no\.?)?\s*|account\s*(?:ending\s*(?:in|with)?\s*)?)(?:[Xx*]{2,8}|[0-9]{2,8})([0-9]{4})/i,

  // Indian Financial System Code (IFSC)
  IFSC_CODE: /\b([A-Z]{4}0[A-Z0-9]{6})\b/g,

  // Permanent Account Number (PAN)
  INDIAN_PAN: /\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b/g,

  // PhonePe Transaction ID (e.g. T2610141422019912038471)
  PHONEPE_TXID: /\b(T[0-9]{12,28})\b/g,

  // Google Pay Reference ID (e.g. CICAg...)
  GPAY_REF_ID: /\b(CICAg[A-Za-z0-9_-]{10,24})\b/g,

  // TRC-20 USDT Address (Tron Base58 starting with T, exactly 34 chars)
  TRON_USDT_ADDRESS: /\b(T[A-Za-z1-9]{33})\b/g,

  // Ethereum / EVM Address
  ETH_EVM_ADDRESS: /\b(0x[a-fA-F0-9]{40})\b/g,

  // Bitcoin Address (Legacy, P2SH, Bech32)
  BITCOIN_ADDRESS: /\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,

  // Telegram Bot Token (bot1234567890:ABCdef...)
  TELEGRAM_BOT_TOKEN: /(?:bot)?([0-9]{8,11}:[A-Za-z0-9_-]{35})/g,

  // Indian Mobile Number (10 digits starting with 6, 7, 8, 9)
  INDIAN_PHONE: /\b(?:\+?91[\-\s]?)?([6-9][0-9]{9})\b/g
};

export function extractUtrFromText(text: string): string | null {
  if (!text) return null;
  // Match "UTR: 123456789012" or "Ref No: 123456789012" or "UPI/123456789012"
  const utrContextMatch = /(?:UTR|RRN|Ref\s*(?:no\.?)?|UPI(?:\/|\s*ref))\s*[:\-]?\s*([0-9]{12})/i.exec(text);
  if (utrContextMatch) {
    return utrContextMatch[1];
  }
  const genericMatch = /\b([0-9]{12})\b/.exec(text);
  return genericMatch ? genericMatch[1] : null;
}

export function extractVpaFromText(text: string): string | null {
  if (!text) return null;
  const match = INDIAN_LEA_REGEX.UPI_VPA_SPECIFIC.exec(text);
  if (match) return match[0];
  const genMatch = INDIAN_LEA_REGEX.UPI_VPA_GENERIC.exec(text);
  return genMatch ? genMatch[0] : null;
}

export function extractAmountInr(text: string): number | null {
  if (!text) return null;
  // Match "Rs. 45,000.00" or "INR 45000" or "debited by 45,000"
  const m = /(?:Rs\.?|INR|\u20B9)\s*([0-9,]+(?:\.[0-9]{1,2})?)/i.exec(text);
  if (m) {
    const cleaned = m[1].replace(/,/g, '');
    const num = parseFloat(cleaned);
    return isNaN(num) ? null : num;
  }
  return null;
}

export function extractAccountMask(text: string): string | null {
  if (!text) return null;
  const m = INDIAN_LEA_REGEX.BANK_ACCOUNT_MASK.exec(text);
  if (m) {
    return `XX${m[1]}`;
  }
  return null;
}
